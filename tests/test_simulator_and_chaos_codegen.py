"""Comprehensive test suite for ConcurrencyGuard Deterministic Async Interleaving Simulator and Chaos Codegen."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import _combine_reproducers, app
from concurrency_guard.scanner.ast_rules import scan_project
from concurrency_guard.simulator import (
    extract_execution_steps,
    simulate_finding,
)

runner = CliRunner()

CG004_CHECK_THEN_ACT_CODE = """from sqlalchemy import select

async def register_user(db, username: str):
    stmt = select(User).where(User.username == username)
    existing = await db.scalar(stmt)
    if existing is None:
        user = User(username=username)
        db.add(user)
        await db.commit()
"""

SAFE_LOCKED_CODE = """from sqlalchemy import select

async def safe_withdraw(db, user_id: int, amount: float):
    stmt = select(Wallet).where(Wallet.user_id == user_id).with_for_update()
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""


def test_cg001_interleaving_trace_accuracy() -> None:
    wallet_file = Path("examples/vulnerable_wallet.py")
    assert wallet_file.is_file(), "examples/vulnerable_wallet.py must exist"

    findings = scan_project([wallet_file], roots=[wallet_file.parent])
    cg001_findings = [f for f in findings if f.rule_id == "CG-001" and f.function_name == "withdraw"]
    assert len(cg001_findings) == 1, f"Expected 1 CG-001 finding, got {len(cg001_findings)}"

    finding = cg001_findings[0]
    read_line, mutate_line, commit_line, steps = extract_execution_steps(finding)
    assert read_line == 52
    assert mutate_line == 62
    assert commit_line == 63
    step_types = [s.step_type for s in steps]
    assert "READ" in step_types
    assert "YIELD_BOUNDARY" in step_types
    assert "MUTATE" in step_types
    assert "COMMIT" in step_types

    trace = simulate_finding(finding, workers=2)
    assert trace.function_name == "withdraw"
    assert trace.rule_id == "CG-001"
    assert trace.read_line == 52
    assert trace.mutate_line == 62
    assert trace.commit_line == 63
    assert trace.anomaly is not None
    assert "Lost Update / Double-Spend" in trace.anomaly.anomaly_type
    assert len(trace.timeline) >= 4

    trace_dict = trace.to_dict()
    assert trace_dict["function_name"] == "withdraw"
    assert trace_dict["rule_id"] == "CG-001"
    assert trace_dict["anomaly"]["anomaly_type"] == trace.anomaly.anomaly_type


def test_cg004_check_then_act_trace(tmp_path: Path) -> None:
    p = tmp_path / "check_act.py"
    p.write_text(CG004_CHECK_THEN_ACT_CODE, encoding="utf-8")

    findings = scan_project([p], roots=[tmp_path])
    cg004_findings = [f for f in findings if f.rule_id == "CG-004"]
    assert len(cg004_findings) == 1, f"Expected 1 CG-004 finding, got {len(cg004_findings)}"

    trace = simulate_finding(cg004_findings[0], workers=2)
    assert trace.function_name == "register_user"
    assert trace.rule_id == "CG-004"
    assert trace.anomaly is not None
    assert "Check-Then-Act Uniqueness Collision" in trace.anomaly.anomaly_type

    step_types = [s.step_type for s in trace.steps]
    assert "CHECK" in step_types
    assert "YIELD_BOUNDARY" in step_types
    assert "ACT" in step_types
    assert "COMMIT" in step_types


def test_cg002_idempotency_retry_trace() -> None:
    wallet_file = Path("examples/vulnerable_wallet.py")
    findings = scan_project([wallet_file], roots=[wallet_file.parent])
    cg002_findings = [f for f in findings if f.rule_id == "CG-002" and f.function_name == "withdraw"]
    assert len(cg002_findings) == 1

    trace = simulate_finding(cg002_findings[0], workers=2)
    assert trace.rule_id == "CG-002"
    assert trace.anomaly is not None
    assert "Non-Idempotent Duplicate Execution" in trace.anomaly.anomaly_type


def test_export_test_valid_ast_and_runnable_pytest(tmp_path: Path) -> None:
    wallet_file = Path("examples/vulnerable_wallet.py")
    out_file = tmp_path / "test_repro.py"

    result = runner.invoke(
        app,
        [
            "simulate",
            str(wallet_file),
            "--rule",
            "CG-001",
            "--export-test",
            str(out_file),
        ],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert out_file.is_file(), "Exported test file must exist"

    code = out_file.read_text(encoding="utf-8")
    parsed = ast.parse(code)
    assert isinstance(parsed, ast.Module)

    # Execute the generated chaos reproducer test using pytest
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(out_file), "-v"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"pytest failed on generated reproducer:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "2 passed" in proc.stdout


def test_clean_safe_file_simulation(tmp_path: Path) -> None:
    p = tmp_path / "safe.py"
    p.write_text(SAFE_LOCKED_CODE, encoding="utf-8")
    out_file = tmp_path / "safe_test.py"

    result = runner.invoke(
        app,
        [
            "simulate",
            str(p),
            "--export-test",
            str(out_file),
        ],
    )
    assert result.exit_code == 0
    assert "No race conditions found to simulate" in result.output
    assert out_file.is_file()
    assert "0 race conditions found" in out_file.read_text(encoding="utf-8")


def test_simulate_format_json() -> None:
    wallet_file = Path("examples/vulnerable_wallet.py")
    result = runner.invoke(
        app,
        [
            "simulate",
            str(wallet_file),
            "--rule",
            "CG-001",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["simulated_findings"] == 1
    assert len(data["traces"]) == 1
    trace_data = data["traces"][0]
    assert trace_data["rule_id"] == "CG-001"
    assert trace_data["function_name"] == "withdraw"
    assert "Lost Update / Double-Spend" in trace_data["anomaly"]["anomaly_type"]


def test_simulate_multi_workers() -> None:
    wallet_file = Path("examples/vulnerable_wallet.py")
    result = runner.invoke(
        app,
        [
            "simulate",
            str(wallet_file),
            "--rule",
            "CG-001",
            "--workers",
            "4",
        ],
    )
    assert result.exit_code == 0
    assert "Async Interleaving Schedule" in result.output
    assert "Coroutine D" in result.output or "Worker 4" in result.output or "Coroutine C" in result.output


def test_simulate_invalid_format_raises_error() -> None:
    wallet_file = Path("examples/vulnerable_wallet.py")
    result = runner.invoke(
        app,
        [
            "simulate",
            str(wallet_file),
            "--format",
            "unsupported_fmt",
        ],
    )
    assert result.exit_code != 0
    assert "format must be one of: table, json" in result.output


def test_combine_reproducers_empty_and_multiple() -> None:
    # Empty traces
    assert "0 race conditions" in _combine_reproducers([])

    wallet_file = Path("examples/vulnerable_wallet.py")
    findings = scan_project([wallet_file], roots=[wallet_file.parent])
    traces = [simulate_finding(f) for f in findings]
    assert len(traces) == 2

    combined = _combine_reproducers(traces)
    parsed = ast.parse(combined)
    assert isinstance(parsed, ast.Module)
    assert "Finding #1" in combined
    assert "Finding #2" in combined

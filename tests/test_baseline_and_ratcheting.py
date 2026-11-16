"""Comprehensive test suite for ConcurrencyGuard baseline and technical debt ratcheting engine."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.baseline import Baseline
from concurrency_guard.cli import app

runner = CliRunner()

LEGACY_THREE_BUGS_CODE = """from sqlalchemy import select

async def withdraw_alpha(db, user_id: int, amount: float):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()

async def withdraw_beta(db, user_id: int, amount: float):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()

async def withdraw_gamma(db, user_id: int, amount: float):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""


def test_baseline_creation_and_clean_ci_pass(tmp_path: Path) -> None:
    """Test 1: Create a legacy repo with 3 CG-001 bugs, baseline it, and verify CI passes cleanly."""
    source_file = tmp_path / "wallet_service.py"
    source_file.write_text(LEGACY_THREE_BUGS_CODE, encoding="utf-8")
    baseline_file = tmp_path / ".cguard-baseline.json"

    # Step 1: Scan without baseline -> fails with 3 active findings
    res_initial = runner.invoke(app, ["scan", str(tmp_path), "--no-cache"])
    assert res_initial.exit_code == 1
    assert "Found 3 concurrency vulnerability issue(s)" in res_initial.output

    # Step 2: Create baseline
    res_create = runner.invoke(
        app,
        ["baseline", "create", str(tmp_path), "--output", str(baseline_file)],
    )
    assert res_create.exit_code == 0
    assert baseline_file.is_file()

    loaded = Baseline.load(baseline_file)
    assert loaded.total_baselined == 3
    assert len(loaded.findings) == 3
    for entry in loaded.findings:
        assert entry.rule_id == "CG-001"
        assert entry.file == "wallet_service.py"
        assert entry.fingerprint
        assert entry.message

    # Step 3: Scan with baseline -> passes with 0 new findings
    res_scan = runner.invoke(
        app,
        ["scan", str(tmp_path), "--baseline", str(baseline_file), "--no-cache"],
    )
    assert res_scan.exit_code == 0
    assert "All AST concurrency checks passed" in res_scan.output
    assert "Baselined: 3 suppressed | New: 0 active | Resolved: 0 fixed" in res_scan.output


def test_baseline_line_shift_immunity(tmp_path: Path) -> None:
    """Test 2: Prepend 25 lines of comments and imports; verify 0 regressions despite line shifts."""
    source_file = tmp_path / "wallet_service.py"
    source_file.write_text(LEGACY_THREE_BUGS_CODE, encoding="utf-8")
    baseline_file = tmp_path / ".cguard-baseline.json"

    # Create baseline
    res_create = runner.invoke(
        app,
        ["baseline", "create", str(tmp_path), "--output", str(baseline_file)],
    )
    assert res_create.exit_code == 0

    # Shift code downward by adding 25 comment lines at top
    comments_prefix = "\n".join(f"# Header license comment line {i}" for i in range(1, 26)) + "\n\n"
    shifted_code = comments_prefix + LEGACY_THREE_BUGS_CODE
    source_file.write_text(shifted_code, encoding="utf-8")

    # Scan with baseline -> must still pass with 0 regressions
    res_scan = runner.invoke(
        app,
        ["scan", str(tmp_path), "--baseline", str(baseline_file), "--no-cache"],
    )
    assert res_scan.exit_code == 0
    assert "All AST concurrency checks passed" in res_scan.output
    assert "Baselined: 3 suppressed | New: 0 active | Resolved: 0 fixed" in res_scan.output


def test_baseline_new_bug_regression_detection(tmp_path: Path) -> None:
    """Test 3: Adding 1 new unlocked endpoint flags ONLY that 1 new bug and exits 1."""
    source_file = tmp_path / "wallet_service.py"
    source_file.write_text(LEGACY_THREE_BUGS_CODE, encoding="utf-8")
    baseline_file = tmp_path / ".cguard-baseline.json"

    # Create baseline for initial 3 bugs
    runner.invoke(
        app,
        ["baseline", "create", str(tmp_path), "--output", str(baseline_file)],
    )

    # Append 1 new unlocked endpoint
    new_bug_code = (
        LEGACY_THREE_BUGS_CODE
        + """
async def withdraw_delta(db, user_id: int, amount: float):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    )
    source_file.write_text(new_bug_code, encoding="utf-8")

    # Scan with baseline -> detects only the new withdraw_delta finding
    res_scan = runner.invoke(
        app,
        ["scan", str(tmp_path), "--baseline", str(baseline_file), "--no-cache"],
    )
    assert res_scan.exit_code == 1
    assert "withdraw_d" in res_scan.output
    assert "Found 1 concurrency vulnerability issue(s)" in res_scan.output
    assert "Baselined: 3 suppressed | New: 1 active | Resolved: 0 fixed" in res_scan.output


def test_baseline_debt_ratcheting_with_update_baseline(tmp_path: Path) -> None:
    """Test 4: Fix 1 baselined bug; verify baseline shrinks from 3 to 2 entries via --update-baseline."""
    source_file = tmp_path / "wallet_service.py"
    source_file.write_text(LEGACY_THREE_BUGS_CODE, encoding="utf-8")
    baseline_file = tmp_path / ".cguard-baseline.json"

    # Create baseline
    runner.invoke(
        app,
        ["baseline", "create", str(tmp_path), "--output", str(baseline_file)],
    )
    assert Baseline.load(baseline_file).total_baselined == 3

    # Fix withdraw_alpha by adding .with_for_update()
    fixed_code = LEGACY_THREE_BUGS_CODE.replace(
        "stmt = select(Wallet).where(Wallet.user_id == user_id)",
        "stmt = select(Wallet).where(Wallet.user_id == user_id).with_for_update()",
        1,
    )
    source_file.write_text(fixed_code, encoding="utf-8")

    # Scan with --update-baseline
    res_update = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--baseline",
            str(baseline_file),
            "--update-baseline",
            "--no-cache",
        ],
    )
    assert res_update.exit_code == 0
    assert "Baselined: 2 suppressed | New: 0 active | Resolved: 1 fixed" in res_update.output

    # Baseline file must now have exactly 2 entries (debt ratcheted downward)
    updated_baseline = Baseline.load(baseline_file)
    assert updated_baseline.total_baselined == 2
    assert len(updated_baseline.findings) == 2
    functions_in_baseline = {e.function for e in updated_baseline.findings}
    assert functions_in_baseline == {"withdraw_beta", "withdraw_gamma"}
    assert "withdraw_alpha" not in functions_in_baseline


def test_baseline_pyproject_toml_integration(tmp_path: Path) -> None:
    """Test 5: [tool.cguard] baseline = '.cguard-baseline.json' is automatically picked up."""
    source_file = tmp_path / "wallet_service.py"
    source_file.write_text(LEGACY_THREE_BUGS_CODE, encoding="utf-8")
    baseline_file = tmp_path / ".cguard-baseline.json"

    # Create baseline file
    runner.invoke(
        app,
        ["baseline", "create", str(tmp_path), "--output", str(baseline_file)],
    )

    # Configure pyproject.toml
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.cguard]
baseline = ".cguard-baseline.json"
""",
        encoding="utf-8",
    )

    # Scan directory without passing --baseline
    res_scan = runner.invoke(app, ["scan", str(tmp_path), "--no-cache"])
    assert res_scan.exit_code == 0
    assert "All AST concurrency checks passed" in res_scan.output
    assert "Baselined: 3 suppressed | New: 0 active | Resolved: 0 fixed" in res_scan.output


def test_baseline_fail_on_stale_baseline(tmp_path: Path) -> None:
    """Verify --fail-on-stale-baseline fails CI when fixed bugs have not been pruned from baseline."""
    source_file = tmp_path / "wallet_service.py"
    source_file.write_text(LEGACY_THREE_BUGS_CODE, encoding="utf-8")
    baseline_file = tmp_path / ".cguard-baseline.json"

    # Create baseline with 3 findings
    runner.invoke(
        app,
        ["baseline", "create", str(tmp_path), "--output", str(baseline_file)],
    )

    # Fix 1 finding without running --update-baseline
    fixed_code = LEGACY_THREE_BUGS_CODE.replace(
        "stmt = select(Wallet).where(Wallet.user_id == user_id)",
        "stmt = select(Wallet).where(Wallet.user_id == user_id).with_for_update()",
        1,
    )
    source_file.write_text(fixed_code, encoding="utf-8")

    # Scan with --fail-on-stale-baseline -> fails with code 1
    res_stale = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--baseline",
            str(baseline_file),
            "--fail-on-stale-baseline",
            "--no-cache",
        ],
    )
    assert res_stale.exit_code == 1
    assert "Strict CI failure: baseline contains 1 resolved finding(s)" in res_stale.output
    assert "Baselined: 2 suppressed | New: 0 active | Resolved: 1 fixed" in res_stale.output


def test_baseline_json_format_reporting(tmp_path: Path) -> None:
    """Verify --format json outputs structured baseline metrics."""
    source_file = tmp_path / "wallet_service.py"
    source_file.write_text(LEGACY_THREE_BUGS_CODE, encoding="utf-8")
    baseline_file = tmp_path / ".cguard-baseline.json"

    runner.invoke(
        app,
        ["baseline", "create", str(tmp_path), "--output", str(baseline_file)],
    )

    res_json = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--baseline",
            str(baseline_file),
            "--format",
            "json",
            "--no-cache",
        ],
    )
    assert res_json.exit_code == 0
    payload = json.loads(res_json.output)
    assert payload["findings_count"] == 0
    assert payload["baseline"]["baselined_count"] == 3
    assert payload["baseline"]["new_count"] == 0
    assert payload["baseline"]["resolved_count"] == 0
    assert "Baselined: 3 suppressed | New: 0 active | Resolved: 0 fixed" in payload["baseline"]["summary"]

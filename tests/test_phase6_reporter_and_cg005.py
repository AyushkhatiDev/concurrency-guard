"""Tests for Phase 6: Rule CG-005, PR reporter, and CLI report command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.reporter.github_pr import generate_github_pr_markdown
from concurrency_guard.scanner.ast_rules import ASTFinding, scan_source_code

runner = CliRunner()


def test_detects_cg005_non_idempotent_celery_retry() -> None:
    """CG-005: Task with autoretry_for/max_retries and DB mutations without acks_late=True or lock."""
    code = """
from celery import shared_task

@shared_task(autoretry_for=(Exception,), max_retries=3)
def process_payout(payout_id: int):
    session = SessionLocal()
    payout = session.query(Payout).get(payout_id)
    payout.status = "COMPLETED"
    session.add(payout)
    session.commit()
"""
    findings = scan_source_code(code)
    cg005_findings = [f for f in findings if f.rule_id == "CG-005"]
    assert len(cg005_findings) == 1
    f = cg005_findings[0]
    assert f.function_name == "process_payout"
    assert "Celery task configured with retries" in f.message
    assert "acks_late=True" in f.suggested_fix_hint


def test_ignores_cg005_celery_task_with_acks_late() -> None:
    """Tasks with acks_late=True or an idempotency/dedup lock must not trigger CG-005."""
    code_acks_late = """
from celery import Celery

app = Celery("tasks")

@app.task(autoretry_for=(Exception,), max_retries=3, acks_late=True)
def safe_payout_with_acks(payout_id: int):
    session = SessionLocal()
    session.add(payout)
    session.commit()
"""
    findings = scan_source_code(code_acks_late)
    assert not any(f.rule_id == "CG-005" for f in findings)

    code_with_lock = """
from celery import shared_task

@shared_task(max_retries=5)
def safe_payout_with_lock(payout_id: int):
    with redis_lock(f"payout:{payout_id}"):
        session = SessionLocal()
        session.add(payout)
        session.commit()
"""
    findings2 = scan_source_code(code_with_lock)
    assert not any(f.rule_id == "CG-005" for f in findings2)


def test_github_pr_markdown_generation() -> None:
    """Generate Markdown report and verify table, exploit proof, and diff collapsible sections."""
    finding = ASTFinding(
        rule_id="CG-001",
        filename="app/wallet.py",
        lineno=25,
        function_name="withdraw",
        message="Unlocked Read-Modify-Write Race Condition",
        suggested_fix_hint="Add .with_for_update()",
    )
    barrier_result = {
        "workers": 20,
        "initial_balance": 50,
        "success_count": 20,
        "final_balance": -950,
        "invariant_violated": True,
    }
    original_code = "select(Wallet).where(Wallet.id == 1)\n"
    patched_code = "select(Wallet).where(Wallet.id == 1).with_for_update()\n"

    md = generate_github_pr_markdown(
        file_path=Path("app/wallet.py"),
        findings=[finding],
        barrier_result=barrier_result,
        patched_code=patched_code,
        original_code=original_code,
    )

    assert "## 🚨 ConcurrencyGuard Verification Report" in md
    assert "| Rule ID | Location | Function | Issue | Suggested Fix |" in md
    assert "`CG-001`" in md
    assert "line 25" in md
    assert "withdraw" in md
    assert "### 💥 Runtime Concurrency Exploit Proof" in md
    assert "Invariant Violation Confirmed" in md
    assert "$-950" in md
    assert "<details>" in md
    assert "<summary>🔧 Deterministic LibCST Auto-Patch Diff</summary>" in md
    assert "+select(Wallet).where(Wallet.id == 1).with_for_update()" in md


def test_cli_report_command_writes_markdown(tmp_path: Path) -> None:
    """CLI cguard report creates output markdown report with findings."""
    vulnerable_file = Path("examples/vulnerable_wallet.py")
    output_md = tmp_path / "pr_report.md"

    result = runner.invoke(app, ["report", str(vulnerable_file), "--output", str(output_md)])
    assert result.exit_code == 1  # Exits with 1 due to detected vulnerabilities
    assert output_md.is_file()

    content = output_md.read_text(encoding="utf-8")
    assert "## 🚨 ConcurrencyGuard Verification Report" in content
    assert "`CG-001`" in content
    assert "`CG-002`" in content
    assert "💥 Runtime Concurrency Exploit Proof" in content
    assert "🔧 Deterministic LibCST Auto-Patch Diff" in content

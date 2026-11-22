"""Tests for Executive Concurrency Health Scorer & Interactive Reports (v3.8.0)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.report import (
    compute_audit_metrics,
    render_html_report,
)
from concurrency_guard.scanner.ast_rules import ASTFinding, scan_file

runner = CliRunner()

CLEAN_CODE = """
def add(a: int, b: int) -> int:
    return a + b
"""

VULNERABLE_CG001_CODE = """
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

async def transfer_funds(db: AsyncSession, wallet_id: int, amount: float):
    result = await db.execute(select(Wallet).where(Wallet.id == wallet_id))
    wallet = result.scalar_one_or_none()
    wallet.balance -= amount
    await db.commit()
"""

VULNERABLE_CG025_AND_CG026 = """
import asyncio
import time

async def worker():
    # CG-025: Blocking call in async def
    time.sleep(1)
    # CG-026: Orphan asyncio task
    asyncio.create_task(worker())
"""

XSS_MALICIOUS_CODE = """
import time

# XSS Attack in comments: <script>alert('pwned_comment')</script>
async def vulnerable_checkout():
    payload = "<script>alert('xss_string')</script>"
    time.sleep(2)  # <script>alert(1)</script>
"""


def test_health_score_and_grading(tmp_path: Path) -> None:
    """Test 1: Clean repo scores 100 (A); vulnerable repos score < 100 with accurate grading."""
    # 1. Clean repo
    clean_file = tmp_path / "clean_service.py"
    clean_file.write_text(CLEAN_CODE, encoding="utf-8")
    clean_findings = scan_file(clean_file)
    clean_metrics = compute_audit_metrics(clean_findings, scanned_files=[clean_file])

    assert clean_metrics.health_score == 100
    assert clean_metrics.grade == "A"
    assert clean_metrics.total_findings == 0
    assert clean_metrics.clean_files_count == 1
    assert len(clean_metrics.hotspots) == 0

    # 2. Single HIGH finding (CG-001: deduction 12 -> 88, Grade B)
    vuln_file_1 = tmp_path / "wallet_service.py"
    vuln_file_1.write_text(VULNERABLE_CG001_CODE, encoding="utf-8")
    findings_1 = scan_file(vuln_file_1)
    assert any(f.rule_id == "CG-001" for f in findings_1)

    metrics_1 = compute_audit_metrics(findings_1, scanned_files=[clean_file, vuln_file_1])
    assert metrics_1.total_findings == 1
    assert metrics_1.high_count == 1
    assert metrics_1.health_score == 88  # 100 - 12
    assert metrics_1.grade == "B"
    assert metrics_1.auto_fixable_count == 1
    assert len(metrics_1.hotspots) == 1
    assert metrics_1.hotspots[0].risk_score == 12

    # 3. Multiple mixed findings (CG-025 HIGH (-12) + CG-026 MEDIUM (-5) -> 83, Grade B)
    vuln_file_2 = tmp_path / "async_tasks.py"
    vuln_file_2.write_text(VULNERABLE_CG025_AND_CG026, encoding="utf-8")
    findings_2 = scan_file(vuln_file_2)
    assert any(f.rule_id == "CG-025" for f in findings_2)
    assert any(f.rule_id == "CG-026" for f in findings_2)

    metrics_2 = compute_audit_metrics(findings_2, scanned_files=[vuln_file_2])
    assert metrics_2.high_count == 1  # CG-025 is HIGH
    assert metrics_2.medium_count == 1  # CG-026 is MEDIUM
    assert metrics_2.health_score == 83  # 100 - 12 - 5
    assert metrics_2.grade == "B"
    assert metrics_2.auto_fixable_count == 1  # CG-025 is auto-fixable, CG-026 is manual

    # 4. Severe findings dropping to F (<60)
    mock_high_findings = [
        ASTFinding(
            rule_id="CG-001",
            filename=f"file_{i}.py",
            lineno=10,
            function_name="mutate",
            message="Unlocked RMW",
            suggested_fix_hint="Lock it",
        )
        for i in range(5)
    ]
    metrics_severe = compute_audit_metrics(mock_high_findings)
    # 5 * 12 = 60 deduction -> 40, Grade F
    assert metrics_severe.health_score == 40
    assert metrics_severe.grade == "F"


def test_html_structure_and_xss_escaping(tmp_path: Path) -> None:
    """Test 2: HTML report is 100% offline-safe, valid HTML5, and strictly escapes XSS injection payloads."""
    malicious_file = tmp_path / "xss_exploit.py"
    malicious_file.write_text(XSS_MALICIOUS_CODE, encoding="utf-8")

    findings = scan_file(malicious_file)
    assert len(findings) > 0

    metrics = compute_audit_metrics(findings, scanned_files=[malicious_file])
    html_output = render_html_report(metrics, findings, scanned_files=[malicious_file])

    # 1. Valid HTML5 document structure
    assert "<!DOCTYPE html>" in html_output
    assert "<html lang=\"en\">" in html_output
    assert "</html>" in html_output

    # 2. Offline safety: zero external CDN / script / stylesheet links
    assert "https://" not in html_output or "https://concurrencyguard.dev" in html_output
    assert "http://" not in html_output
    assert "<script src=" not in html_output
    assert "<link rel=\"stylesheet\" href=\"http" not in html_output

    # 3. Strict XSS Safety: <script> must be escaped to &lt;script&gt;
    assert "<script>alert(1)</script>" not in html_output
    assert "<script>alert('pwned_comment')</script>" not in html_output
    assert "<script>alert('xss_string')</script>" not in html_output
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_output
    assert "&lt;script&gt;alert(&#x27;xss_string&#x27;)&lt;/script&gt;" in html_output or "&lt;script&gt;alert('xss_string')&lt;/script&gt;" in html_output

    # 4. Executive KPI cards and interactive UI elements
    assert "Executive Concurrency Health Report" in html_output
    assert "Health Score" in html_output
    assert "Total Findings" in html_output
    assert "Top Hotspot Files" in html_output
    assert "CWE Compliance Breakdown" in html_output
    assert "data-severity" in html_output
    assert "data-rule" in html_output


def test_markdown_report_output(tmp_path: Path) -> None:
    """Test 3: cguard report <path> --format markdown outputs a clean, well-formatted Markdown summary."""
    vuln_file = tmp_path / "order_service.py"
    vuln_file.write_text(VULNERABLE_CG001_CODE, encoding="utf-8")

    # CLI invocation with --format markdown
    result = runner.invoke(app, ["report", str(tmp_path), "--format", "markdown"])
    assert result.exit_code == 0

    output = result.output
    assert "# 🛡️ ConcurrencyGuard Executive Concurrency Audit Report" in output
    assert "## 📊 Executive Summary" in output
    assert "| Health Score | Letter Grade | Total Findings |" in output
    assert "## 🎯 Top Hotspot Files" in output
    assert "## 🏷️ CWE Compliance Breakdown" in output
    assert "## 🔍 Detailed Concurrency Findings" in output
    assert "`CG-001`" in output
    assert "order_service.py" in output

    # Write to file with --output
    out_md = tmp_path / "audit_report.md"
    file_result = runner.invoke(app, ["report", str(tmp_path), "--format", "markdown", "--output", str(out_md)])
    assert file_result.exit_code == 0
    assert out_md.is_file()
    saved_content = out_md.read_text(encoding="utf-8")
    assert "# 🛡️ ConcurrencyGuard Executive Concurrency Audit Report" in saved_content


def test_min_score_ci_quality_gate(tmp_path: Path) -> None:
    """Test 4: --min-score quality gate exits 1 on failure and 0 on pass."""
    clean_dir = tmp_path / "clean_project"
    clean_dir.mkdir()
    (clean_dir / "math_utils.py").write_text(CLEAN_CODE, encoding="utf-8")

    vuln_dir = tmp_path / "vuln_project"
    vuln_dir.mkdir()
    (vuln_dir / "wallet.py").write_text(VULNERABLE_CG001_CODE, encoding="utf-8")

    # 1. Clean repo with min-score 95 -> score is 100 >= 95 -> exits 0
    clean_res = runner.invoke(app, ["report", str(clean_dir), "--min-score", "95"])
    assert clean_res.exit_code == 0
    assert "CI Quality Gate Passed" in clean_res.output
    assert "100/100" in clean_res.output

    # 2. Vulnerable repo with min-score 95 -> score is 88 < 95 -> exits 1
    vuln_res = runner.invoke(app, ["report", str(vuln_dir), "--min-score", "95"])
    assert vuln_res.exit_code == 1
    assert "CI Quality Gate Failed" in vuln_res.output
    assert "88/100" in vuln_res.output

    # 3. Vulnerable repo with min-score 80 -> score is 88 >= 80 -> exits 0
    lenient_res = runner.invoke(app, ["report", str(vuln_dir), "--min-score", "80"])
    assert lenient_res.exit_code == 0
    assert "CI Quality Gate Passed" in lenient_res.output


def test_json_report_format(tmp_path: Path) -> None:
    """Test 5: cguard report --format json emits valid, parseable JSON dictionary."""
    vuln_file = tmp_path / "tasks.py"
    vuln_file.write_text(VULNERABLE_CG025_AND_CG026, encoding="utf-8")

    res = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0

    data = json.loads(res.output)
    assert "health_score" in data
    assert "grade" in data
    assert "total_findings" in data
    assert data["total_findings"] >= 2
    assert "hotspots" in data
    assert "cwe_breakdown" in data
    assert "rule_breakdown" in data
    assert data["rule_breakdown"].get("CG-025", 0) >= 1

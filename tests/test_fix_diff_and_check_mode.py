"""Tests for cguard fix --diff, --check, --rule, and JSON output formatting."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.patcher.cst_fixer import (
    apply_all_fixes,
    apply_all_fixes_with_report,
    fix_file,
)

runner = CliRunner()

VULNERABLE_CG001_CODE = """from sqlalchemy import select

async def update_balance(db, user_id, amount):
    stmt = select(Account).where(Account.id == user_id)
    res = await db.execute(stmt)
    account = res.scalar_one_or_none()
    account.balance += amount
    await db.commit()
"""

CLEAN_CG001_CODE = """from sqlalchemy import select

async def update_balance(db, user_id, amount):
    stmt = select(Account).where(Account.id == user_id).with_for_update()
    res = await db.execute(stmt)
    account = res.scalar_one_or_none()
    account.balance += amount
    await db.commit()
"""

VULNERABLE_CG001_AND_CG002_CODE = """from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

app = FastAPI()

@app.post("/transfer")
async def transfer_funds(user_id: int, amount: float, db: AsyncSession = Depends()):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = (await db.execute(stmt)).scalar_one()
    wallet.balance += amount
    await db.commit()
    return {"status": "ok"}
"""


def test_diff_immutability_and_diff_accuracy(tmp_path: Path) -> None:
    """Test 1: Run cguard fix <file> --diff on a vulnerable CG-001 file.

    Verifies stdout contains '--- a/', '+++ b/', and '+.with_for_update()',
    and verifies the file on disk remains 100% unmodified (byte-for-byte identical).
    """
    target = tmp_path / "vulnerable_wallet.py"
    target.write_text(VULNERABLE_CG001_CODE, encoding="utf-8")

    result = runner.invoke(app, ["fix", str(target), "--diff"])

    assert result.exit_code == 0
    assert "--- a/" in result.stdout
    assert "+++ b/" in result.stdout
    assert ".with_for_update()" in result.stdout

    # File on disk must remain strictly identical
    disk_content = target.read_text(encoding="utf-8")
    assert disk_content == VULNERABLE_CG001_CODE
    assert ".with_for_update()" not in disk_content


def test_check_mode_exit_codes(tmp_path: Path) -> None:
    """Test 2: Run cguard fix <file> --check.

    Verifies exit code is 1 and file on disk is untouched when vulnerable.
    Verifies exit code is 0 when the file is already clean.
    """
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text(VULNERABLE_CG001_CODE, encoding="utf-8")

    clean_file = tmp_path / "clean.py"
    clean_file.write_text(CLEAN_CG001_CODE, encoding="utf-8")

    # 1. Vulnerable file check -> exits 1, disk unmodified
    res_vuln = runner.invoke(app, ["fix", str(vuln_file), "--check"])
    assert res_vuln.exit_code == 1
    assert vuln_file.read_text(encoding="utf-8") == VULNERABLE_CG001_CODE

    # 2. Clean file check -> exits 0
    res_clean = runner.invoke(app, ["fix", str(clean_file), "--check"])
    assert res_clean.exit_code == 0
    assert clean_file.read_text(encoding="utf-8") == CLEAN_CG001_CODE


def test_check_and_diff_combined_mode(tmp_path: Path) -> None:
    """Test 3: Run cguard fix <file> --check --diff combined mode.

    Verifies running both flags prints the unified diff AND exits with code 1 without touching disk.
    """
    target = tmp_path / "combined.py"
    target.write_text(VULNERABLE_CG001_CODE, encoding="utf-8")

    result = runner.invoke(app, ["fix", str(target), "--check", "--diff"])

    assert result.exit_code == 1
    assert "--- a/" in result.stdout
    assert "+++ b/" in result.stdout
    assert ".with_for_update()" in result.stdout
    assert target.read_text(encoding="utf-8") == VULNERABLE_CG001_CODE


def test_rule_selective_patching(tmp_path: Path) -> None:
    """Test 4: Create a file containing both CG-001 and CG-002 vulnerabilities.

    Run cguard fix <file> --rule CG-001 -> verify ONLY .with_for_update() is injected,
    while route parameters (CG-002 Header) remain untouched.
    """
    target = tmp_path / "service.py"
    target.write_text(VULNERABLE_CG001_AND_CG002_CODE, encoding="utf-8")

    # Fix only CG-001 with --write
    result = runner.invoke(app, ["fix", str(target), "--rule", "CG-001", "--write"])
    assert result.exit_code == 0

    patched_content = target.read_text(encoding="utf-8")
    # CG-001 must be fixed
    assert ".with_for_update()" in patched_content
    # CG-002 must remain unpatched
    assert "idempotency_key" not in patched_content
    assert "Header" not in patched_content

    # Now fix CG-002 with --write
    result_cg002 = runner.invoke(app, ["fix", str(target), "--rule", "CG-002", "--write"])
    assert result_cg002.exit_code == 0

    fully_patched = target.read_text(encoding="utf-8")
    assert ".with_for_update()" in fully_patched
    assert "idempotency_key" in fully_patched
    assert "Header" in fully_patched


def test_json_output_with_diff(tmp_path: Path) -> None:
    """Test 5: Run cguard fix <file> --diff --format json.

    Verifies stdout is valid JSON containing dry_run, would_modify_count, and the unified diff.
    """
    target = tmp_path / "api.py"
    target.write_text(VULNERABLE_CG001_CODE, encoding="utf-8")

    result = runner.invoke(app, ["fix", str(target), "--diff", "--format", "json"])
    assert result.exit_code == 0

    data = json.loads(result.stdout)
    assert data["dry_run"] is True
    assert data["would_modify_count"] == 1
    assert data["total_files"] == 1
    assert "diff" in data
    assert ".with_for_update()" in data["diff"]
    assert len(data["files"]) == 1
    assert data["files"][0]["modified"] is True
    assert ".with_for_update()" in data["files"][0]["diff"]

    # File on disk remains unmodified
    assert target.read_text(encoding="utf-8") == VULNERABLE_CG001_CODE


def test_json_output_in_check_mode(tmp_path: Path) -> None:
    """Verifies cguard fix --check --format json fails CI with code 1 on vulnerable files."""
    target = tmp_path / "api_check.py"
    target.write_text(VULNERABLE_CG001_CODE, encoding="utf-8")

    result = runner.invoke(app, ["fix", str(target), "--check", "--format", "json"])
    assert result.exit_code == 1

    data = json.loads(result.stdout)
    assert data["dry_run"] is True
    assert data["would_modify_count"] == 1
    assert target.read_text(encoding="utf-8") == VULNERABLE_CG001_CODE


def test_selective_rules_comma_separated_and_repeated(tmp_path: Path) -> None:
    """Verifies --rule can be repeated (-r CG-001 -r CG-002) and comma-separated (--rule CG-001,CG-002)."""
    target1 = tmp_path / "ep1.py"
    target1.write_text(VULNERABLE_CG001_AND_CG002_CODE, encoding="utf-8")

    # Repeatable flags
    res1 = runner.invoke(app, ["fix", str(target1), "-r", "CG-001", "-r", "CG-002", "--write"])
    assert res1.exit_code == 0
    content1 = target1.read_text(encoding="utf-8")
    assert ".with_for_update()" in content1
    assert "idempotency_key" in content1

    target2 = tmp_path / "ep2.py"
    target2.write_text(VULNERABLE_CG001_AND_CG002_CODE, encoding="utf-8")

    # Comma-separated flags
    res2 = runner.invoke(app, ["fix", str(target2), "--rule", "CG-001,CG-002", "--write"])
    assert res2.exit_code == 0
    content2 = target2.read_text(encoding="utf-8")
    assert ".with_for_update()" in content2
    assert "idempotency_key" in content2


def test_cst_fixer_fix_file_api(tmp_path: Path) -> None:
    """Verifies fix_file helper function works in dry-run and write mode."""
    target = tmp_path / "test_api.py"
    target.write_text(VULNERABLE_CG001_CODE, encoding="utf-8")

    # Dry-run
    res_dry = fix_file(target, dry_run=True, write_to_disk=True)
    assert res_dry.modified is True
    assert ".with_for_update()" in res_dry.unified_diff
    assert target.read_text(encoding="utf-8") == VULNERABLE_CG001_CODE

    # Write to disk
    res_write = fix_file(target, dry_run=False, write_to_disk=True)
    assert res_write.modified is True
    assert ".with_for_update()" in target.read_text(encoding="utf-8")


def test_apply_all_fixes_with_report_unified_diff() -> None:
    """Verifies apply_all_fixes_with_report populates unified_diff and modified flags."""
    res = apply_all_fixes_with_report(VULNERABLE_CG001_CODE, rules={"CG-001"})
    assert res.modified is True
    assert ".with_for_update()" in res.code
    assert "--- a/file.py" in res.unified_diff
    assert "+++ b/file.py" in res.unified_diff

    # Clean code: modified is False, diff is empty
    res_clean = apply_all_fixes_with_report(CLEAN_CG001_CODE, rules={"CG-001"})
    assert res_clean.modified is False
    assert res_clean.unified_diff == ""


def test_apply_all_fixes_selective_rules() -> None:
    """Verifies apply_all_fixes supports both rules and selected_rules arguments."""
    fixed_r = apply_all_fixes(VULNERABLE_CG001_AND_CG002_CODE, rules={"CG-001"})
    assert ".with_for_update()" in fixed_r
    assert "idempotency_key" not in fixed_r

    fixed_sr = apply_all_fixes(VULNERABLE_CG001_AND_CG002_CODE, selected_rules={"CG-002"})
    assert "idempotency_key" in fixed_sr
    assert ".with_for_update()" not in fixed_sr

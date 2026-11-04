"""Comprehensive test suite for inline # cg:ignore noise-suppression engine."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.scanner.ast_rules import ASTFinding, scan_file
from concurrency_guard.scanner.suppression import SuppressionFilter

runner = CliRunner()


def test_line_level_suppression_matches_exact_line_and_specific_rule(tmp_path: Path) -> None:
    """Line-level suppression matches the exact line and target rule ID."""
    code = """
def test_fn():
    lock.acquire()  # cg:ignore[CG-016]
    lock.release()
"""
    file_path = tmp_path / "target.py"
    file_path.write_text(code, encoding="utf-8")

    sf = SuppressionFilter()
    sf.parse_source(code, filepath=file_path)

    # Line 3 has # cg:ignore[CG-016]
    assert sf.should_suppress("CG-016", file_path, line_number=3) is True
    # Different line for same rule is not suppressed
    assert sf.should_suppress("CG-016", file_path, line_number=4) is False
    # Case insensitivity
    assert sf.should_suppress("cg-016", file_path, line_number=3) is True


def test_line_level_suppression_ignores_other_rules_on_same_line(tmp_path: Path) -> None:
    """Line-level suppression only suppresses listed rules and ignores others on the same line."""
    code = """
def worker():
    with db_lock:  # cg:ignore[CG-016, CG-017] rationale="Intentional cross-lock"
        pass
"""
    file_path = tmp_path / "worker.py"
    file_path.write_text(code, encoding="utf-8")

    sf = SuppressionFilter()
    sf.parse_source(code, filepath=file_path)

    # Line 3 suppresses CG-016 and CG-017
    assert sf.should_suppress("CG-016", file_path, line_number=3) is True
    assert sf.should_suppress("CG-017", file_path, line_number=3) is True
    # Line 3 does NOT suppress CG-001 or CG-002
    assert sf.should_suppress("CG-001", file_path, line_number=3) is False
    assert sf.should_suppress("CG-002", file_path, line_number=3) is False


def test_block_level_suppression(tmp_path: Path) -> None:
    """Block-level suppression suppresses findings between ignore-start and ignore-end."""
    code = """
# cg:ignore-start[CG-016]
with lock_a:
    with lock_b:
        pass
# cg:ignore-end[CG-016]

with lock_c:
    pass
"""
    file_path = tmp_path / "block.py"
    file_path.write_text(code, encoding="utf-8")

    sf = SuppressionFilter()
    sf.parse_source(code, filepath=file_path)

    # Lines 2 to 6 are inside the block
    assert sf.should_suppress("CG-016", file_path, line_number=2) is True
    assert sf.should_suppress("CG-016", file_path, line_number=3) is True
    assert sf.should_suppress("CG-016", file_path, line_number=4) is True
    assert sf.should_suppress("CG-016", file_path, line_number=5) is True
    assert sf.should_suppress("CG-016", file_path, line_number=6) is True

    # Line 8 is outside the block
    assert sf.should_suppress("CG-016", file_path, line_number=8) is False

    # Other rules inside the block are not suppressed
    assert sf.should_suppress("CG-001", file_path, line_number=3) is False


def test_string_literal_comments_are_ignored(tmp_path: Path) -> None:
    """The tokenizer ensures # cg:ignore text inside strings or docstrings is ignored."""
    code = '''
docstring = """
Here is an example comment: # cg:ignore[CG-001]
It should not trigger suppression.
"""
query = "SELECT * FROM users # cg:ignore[CG-001]"
'''
    file_path = tmp_path / "literal.py"
    file_path.write_text(code, encoding="utf-8")

    sf = SuppressionFilter()
    sf.parse_source(code, filepath=file_path)

    # Neither line 3 nor line 6 is a real comment
    assert sf.should_suppress("CG-001", file_path, line_number=3) is False
    assert sf.should_suppress("CG-001", file_path, line_number=6) is False


def test_file_level_suppression(tmp_path: Path) -> None:
    """# cg:ignore-file suppresses the specified rule anywhere in the file."""
    code = """
# cg:ignore-file[CG-001]
x = 1
y = 2
z = 3
"""
    file_path = tmp_path / "file_ignore.py"
    file_path.write_text(code, encoding="utf-8")

    sf = SuppressionFilter()
    sf.parse_source(code, filepath=file_path)

    assert sf.should_suppress("CG-001", file_path, line_number=3) is True
    assert sf.should_suppress("CG-001", file_path, line_number=4) is True
    assert sf.should_suppress("CG-001", file_path, line_number=5) is True
    assert sf.should_suppress("CG-002", file_path, line_number=4) is False


def test_filter_findings_increments_metric(tmp_path: Path) -> None:
    """filter_findings properly filters findings and increments suppressed_count."""
    code = """
x = 1  # cg:ignore[CG-001]
y = 2
"""
    file_path = tmp_path / "target.py"
    file_path.write_text(code, encoding="utf-8")

    sf = SuppressionFilter()
    findings = [
        ASTFinding(rule_id="CG-001", filename=str(file_path), lineno=2, function_name="f", message="", suggested_fix_hint=""),
        ASTFinding(rule_id="CG-001", filename=str(file_path), lineno=3, function_name="f", message="", suggested_fix_hint=""),
    ]

    active = sf.filter_findings(findings, file_path=file_path)
    assert len(active) == 1
    assert active[0].lineno == 3
    assert sf.suppressed_count == 1


def test_scan_file_integration_filters_findings(tmp_path: Path) -> None:
    """scan_file honors # cg:ignore on real vulnerable AST patterns."""
    # Line 4 has unprotected balance deduction without .with_for_update(), but is ignored
    code = """
from sqlalchemy import select

async def withdraw(db, user_id, amount):
    acc = await db.scalar(select(Account).where(Account.id == user_id))  # cg:ignore[CG-001]
    acc.balance -= amount
    await db.commit()
"""
    file_path = tmp_path / "wallet.py"
    file_path.write_text(code, encoding="utf-8")

    findings = scan_file(file_path)
    # CG-001 was suppressed on line 5
    cg001 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001) == 0


def test_cli_summary_outputs_correct_suppressed_count(tmp_path: Path) -> None:
    """CLI summary outputs the exact count of suppressed findings in human and JSON formats."""
    # Vulnerable route with one finding suppressed and one remaining
    code = """
from sqlalchemy import select

async def route_a(db):
    acc = await db.scalar(select(Account))  # cg:ignore[CG-001]
    acc.balance -= 10
    await db.commit()

async def route_b(db):
    acc = await db.scalar(select(Account))
    acc.balance -= 20
    await db.commit()
"""
    file_path = tmp_path / "app.py"
    file_path.write_text(code, encoding="utf-8")

    # Table format CLI run
    res = runner.invoke(app, ["scan", str(file_path), "--no-cache"])
    assert res.exit_code == 1
    assert "(1 suppressed)" in res.stdout
    assert "Found 1 concurrency vulnerability issue(s) (1 suppressed)" in res.stdout or "Found 1 issue(s) (1 suppressed)" in res.stdout

    # JSON format CLI run
    res_json = runner.invoke(app, ["scan", str(file_path), "--format", "json", "--no-cache"])
    assert res_json.exit_code == 1
    data = json.loads(res_json.stdout)
    assert data["findings_count"] == 1
    assert data["suppressed_count"] == 1

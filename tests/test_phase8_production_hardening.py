"""Unit tests for Phase 8: SQLAlchemy 2.0 query patterns, directory filtering, and CLI JSON reporting."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.scanner.ast_rules import (
    discover_python_files,
    scan_directory,
    scan_file,
    scan_source_code,
)

runner = CliRunner()


def test_sqlalchemy2_scalar_unlocked_rmw_detected() -> None:
    """Verify CG-001 catches await db.scalar(select(...)) followed by mutation without .with_for_update()."""
    code = """
async def redeem_coupon(code: str, db: AsyncSession):
    coupon = await db.scalar(select(Coupon).where(Coupon.code == code))
    if coupon and coupon.remaining_uses > 0:
        coupon.remaining_uses -= 1
        await db.commit()
"""
    findings = scan_source_code(code)
    cg001 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001) == 1
    assert cg001[0].function_name == "redeem_coupon"


def test_n_plus_one_detects_scalar_and_get_in_loop() -> None:
    """Verify CG-003 catches await db.scalar(...) and await db.get(...) inside a for loop."""
    code = """
async def process_orders(orders: list[Order], db: AsyncSession):
    for order in orders:
        item = await db.scalar(select(Item).where(Item.order_id == order.id))
        user = await db.get(User, order.user_id)
"""
    findings = scan_source_code(code)
    cg003 = [f for f in findings if f.rule_id == "CG-003"]
    assert len(cg003) == 2
    assert all(f.function_name == "process_orders" for f in cg003)


def test_directory_scanner_skips_venv_and_alembic(tmp_path: Path) -> None:
    """Verify directory scanner skips hidden dirs, .venv, and alembic migration folders."""
    venv_dir = tmp_path / ".venv" / "lib"
    venv_dir.mkdir(parents=True)
    (venv_dir / "bad.py").write_text("x = 1\n", encoding="utf-8")

    alembic_dir = tmp_path / "alembic" / "versions"
    alembic_dir.mkdir(parents=True)
    (alembic_dir / "001.py").write_text("y = 2\n", encoding="utf-8")

    app_dir = tmp_path / "app"
    app_dir.mkdir(parents=True)
    route_file = app_dir / "routes.py"
    route_file.write_text("z = 3\n", encoding="utf-8")

    discovered = discover_python_files(tmp_path)
    assert len(discovered) == 1
    assert discovered[0].resolve() == route_file.resolve()


def test_scan_cli_json_output_format() -> None:
    """Verify cguard scan examples/real_world_ecommerce/ --format json outputs valid JSON with CG-001 to CG-005."""
    result = runner.invoke(app, ["scan", "examples/real_world_ecommerce", "--format", "json"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["scanned_files"] == 4
    assert data["findings_count"] >= 5
    rules = {f["rule_id"] for f in data["findings"]}
    assert {"CG-001", "CG-002", "CG-003", "CG-004", "CG-005"}.issubset(rules)


def test_graceful_handling_of_syntax_error_files(tmp_path: Path) -> None:
    """Verify scanning malformed Python files skips them gracefully without raising exceptions."""
    bad_syntax_file = tmp_path / "broken.py"
    bad_syntax_file.write_text("def broken(:\n    pass\n", encoding="utf-8")

    good_file = tmp_path / "clean.py"
    good_file.write_text("def clean():\n    return 42\n", encoding="utf-8")

    # scan_file returns [] on syntax errors
    assert scan_file(bad_syntax_file) == []

    # scan_directory on directory with broken file doesn't crash
    findings = scan_directory(tmp_path)
    assert findings == []

    # CLI scan also completes cleanly with exit code 0
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No vulnerabilities found" in result.stdout


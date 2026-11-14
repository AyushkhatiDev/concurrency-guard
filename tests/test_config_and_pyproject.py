"""Comprehensive tests for pyproject.toml [tool.cguard] and .cguard.toml configuration engine."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.config import (
    CGuardConfig,
    find_config_file,
    load_cguard_config,
)
from concurrency_guard.scanner.ast_rules import (
    discover_python_files,
    scan_file,
    scan_source_code,
)

runner = CliRunner()


def test_config_precedence_cguard_toml_over_pyproject(tmp_path: Path) -> None:
    """Verify that .cguard.toml takes precedence over pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.cguard]
select = ["CG-001"]
confidence = "medium"
""",
        encoding="utf-8",
    )

    dot_cguard = tmp_path / ".cguard.toml"
    dot_cguard.write_text(
        """
select = ["CG-002"]
confidence = "high"
custom_lock_names = ["cluster_mutex"]
""",
        encoding="utf-8",
    )

    found = find_config_file(tmp_path)
    assert found == dot_cguard

    cfg = load_cguard_config(start_path=tmp_path)
    assert cfg.select == ["CG-002"]
    assert cfg.confidence == "high"
    assert "cluster_mutex" in cfg.custom_lock_names


def test_config_loading_from_pyproject_toml(tmp_path: Path) -> None:
    """Verify loading configuration directly from pyproject.toml [tool.cguard]."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.cguard]
select = ["CG-001", "CG-004"]
ignore = ["CG-003"]
exclude = ["migrations/*", "fixtures"]
confidence = "medium"
jobs = 4
custom_lock_names = ["distributed_tx_lock"]

[tool.cguard.per_file_ignores]
"tests/*" = ["CG-001"]
""",
        encoding="utf-8",
    )

    cfg = load_cguard_config(start_path=tmp_path)
    assert cfg.select == ["CG-001", "CG-004"]
    assert cfg.ignore == ["CG-003"]
    assert cfg.exclude == ["migrations/*", "fixtures"]
    assert cfg.confidence == "medium"
    assert cfg.jobs == 4
    assert cfg.custom_lock_names == ["distributed_tx_lock"]
    assert cfg.per_file_ignores == {"tests/*": ["CG-001"]}


def test_select_and_ignore_filtering() -> None:
    """Verify that select and ignore accurately filter reported findings."""
    code = """
from sqlalchemy import select
from fastapi import FastAPI, Header

app = FastAPI()

# CG-001: Unlocked Read-Modify-Write
async def update_account(db, user_id: int):
    user = await db.scalar(select(User).where(User.id == user_id))
    user.balance -= 50
    await db.commit()

# CG-002: Missing Idempotency-Key
@app.post("/transfer")
async def transfer_money(db, amount: int):
    await db.execute("UPDATE accounts SET balance = balance - 10")
    await db.commit()
"""
    # 1. Unfiltered: reports both CG-001 and CG-002
    all_findings = scan_source_code(code, "route.py")
    rule_ids = {f.rule_id for f in all_findings}
    assert "CG-001" in rule_ids
    assert "CG-002" in rule_ids

    # 2. Whitelist: select only CG-001
    cfg_select = CGuardConfig(select=["CG-001"])
    select_findings = scan_source_code(code, "route.py", config=cfg_select)
    select_rule_ids = {f.rule_id for f in select_findings}
    assert "CG-001" in select_rule_ids
    assert "CG-002" not in select_rule_ids

    # 3. Blacklist: ignore CG-001
    cfg_ignore = CGuardConfig(ignore=["CG-001"])
    ignore_findings = scan_source_code(code, "route.py", config=cfg_ignore)
    ignore_rule_ids = {f.rule_id for f in ignore_findings}
    assert "CG-001" not in ignore_rule_ids
    assert "CG-002" in ignore_rule_ids


def test_per_file_ignores(tmp_path: Path) -> None:
    """Verify that per_file_ignores suppresses findings in matching paths only."""
    cfg = CGuardConfig(
        per_file_ignores={"tests/*": ["CG-001"]},
    )

    code = """
from sqlalchemy import select

async def mutate_balance(db, user_id: int):
    user = await db.scalar(select(User).where(User.id == user_id))
    user.balance -= 50
    await db.commit()
"""
    # Inside tests/ folder -> CG-001 is suppressed
    test_file = tmp_path / "tests" / "test_api.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text(code, encoding="utf-8")

    test_findings = scan_file(test_file, config=cfg)
    assert len([f for f in test_findings if f.rule_id == "CG-001"]) == 0

    # Outside tests/ folder -> CG-001 is reported
    app_file = tmp_path / "app" / "routes.py"
    app_file.parent.mkdir(parents=True, exist_ok=True)
    app_file.write_text(code, encoding="utf-8")

    app_findings = scan_file(app_file, config=cfg)
    assert len([f for f in app_findings if f.rule_id == "CG-001"]) == 1


def test_custom_lock_names_sanitizer() -> None:
    """Verify custom lock context managers act as sanitizers and yield 0 false positives."""
    code = """
from sqlalchemy import select

async def process_transaction(db, user_id: int):
    async with acquire_tenant_guard(user_id):
        user = await db.scalar(select(User).where(User.id == user_id))
        user.balance -= 50
        await db.commit()
"""
    # Without custom lock registered -> flagged as CG-001
    unregistered_findings = scan_source_code(code, "tx.py")
    assert any(f.rule_id == "CG-001" for f in unregistered_findings)

    # With custom lock registered -> 0 findings
    cfg = CGuardConfig(custom_lock_names=["acquire_tenant_guard"])
    registered_findings = scan_source_code(code, "tx.py", config=cfg)
    assert len([f for f in registered_findings if f.rule_id == "CG-001"]) == 0


def test_exclude_patterns_skipping_files(tmp_path: Path) -> None:
    """Verify exclude patterns skip matching directories during file discovery."""
    cfg = CGuardConfig(exclude=["legacy/*", "migrations"])

    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")

    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "old.py").write_text("x = 1\n", encoding="utf-8")

    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations" / "0001_init.py").write_text("x = 1\n", encoding="utf-8")

    discovered = discover_python_files(tmp_path, config=cfg)
    discovered_names = {f.name for f in discovered}

    assert "main.py" in discovered_names
    assert "old.py" not in discovered_names
    assert "0001_init.py" not in discovered_names


def test_cache_invalidation_on_config_change(tmp_path: Path) -> None:
    """Verify that updating pyproject.toml [tool.cguard] invalidates cached scan findings."""
    cache_dir = tmp_path / ".cguard_cache"
    app_file = tmp_path / "app.py"
    app_file.write_text(
        """
from sqlalchemy import select

async def update_balance(db, user_id: int):
    user = await db.scalar(select(User).where(User.id == user_id))
    user.balance -= 50
    await db.commit()
""",
        encoding="utf-8",
    )

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.cguard]
ignore = []
""",
        encoding="utf-8",
    )

    # 1. Initial scan with empty ignore: flags CG-001
    load_cguard_config(start_path=tmp_path)
    res1 = runner.invoke(app, ["scan", str(app_file), "--config", str(pyproject), "--cache-dir", str(cache_dir)])
    assert res1.exit_code == 1
    assert "CG-001" in res1.stdout

    # 2. Modify pyproject.toml to ignore CG-001
    pyproject.write_text(
        """
[tool.cguard]
ignore = ["CG-001"]
""",
        encoding="utf-8",
    )

    # 3. Second scan with cache enabled: config change invalidates cache hash
    res2 = runner.invoke(app, ["scan", str(app_file), "--config", str(pyproject), "--cache-dir", str(cache_dir)])
    assert res2.exit_code == 0
    assert "No vulnerabilities found" in res2.stdout


def test_cli_flags_override_pyproject_config(tmp_path: Path) -> None:
    """Verify CLI options take precedence over pyproject.toml values."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.cguard]
ignore = ["CG-001"]
""",
        encoding="utf-8",
    )

    app_file = tmp_path / "app.py"
    app_file.write_text(
        """
from sqlalchemy import select

async def update_balance(db, user_id: int):
    user = await db.scalar(select(User).where(User.id == user_id))
    user.balance -= 50
    await db.commit()
""",
        encoding="utf-8",
    )

    # In config, CG-001 is ignored -> scan would exit 0
    # Overriding with CLI --select-rule CG-001 re-enables CG-001!
    result = runner.invoke(
        app,
        ["scan", str(app_file), "--config", str(pyproject), "--select-rule", "CG-001"],
    )
    assert result.exit_code == 1
    assert "CG-001" in result.stdout

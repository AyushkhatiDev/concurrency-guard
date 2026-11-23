"""Path-sensitive scanner API and command-line regressions."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from textwrap import indent

from typer.testing import CliRunner

from cguard.cfg import build_function_cfg, compute_locked_paths
from concurrency_guard.cli import app
from concurrency_guard.scanner.ast_rules import scan_source_code

BRANCH = """async def update(session, vip):
    wallet = await session.get(Wallet, 1)
    if vip:
        wallet = await session.scalar(select(Wallet).with_for_update())
    else:
        wallet.balance += 1
    await session.commit()
"""
CACHE = """import asyncio
CACHE = {}
cache_lock = asyncio.Lock()
async def fetch_value(key):
    if key not in CACHE:
        value = await fetch()
        CACHE[key] = value
"""


def test_sibling_mutation() -> None:
    findings = scan_source_code(BRANCH)
    assert [(f.rule_id, f.lineno) for f in findings if f.rule_id in {"CG-028", "CG-001"}] == [
        ("CG-028", 6)
    ]
    safe = BRANCH.replace(
        "        wallet.balance",
        "        wallet = await session.scalar(select(Wallet).with_for_update())\n        wallet.balance",
    )
    assert not scan_source_code(safe)
    no_commit = BRANCH.replace(
        "        wallet.balance += 1", "        wallet.balance += 1\n        return"
    )
    assert not any(f.rule_id == "CG-028" for f in scan_source_code(no_commit))


def test_early_return_and_finally() -> None:
    src = """async def change(session, user):
    if not user:
        return
    try:
        user = await session.scalar(select(User).with_for_update())
        user.count += 1
    finally:
        await session.commit()
"""
    assert not scan_source_code(src)
    fn = ast.parse(src).body[0]
    assert isinstance(fn, ast.AsyncFunctionDef)
    cfg = build_function_cfg(fn)
    stmt = next(s for s in ast.walk(fn) if isinstance(s, ast.AugAssign))
    assert "user" in compute_locked_paths(cfg)[stmt].must


def test_shared_window() -> None:
    def lines(source: str) -> list[int]:
        return [f.lineno for f in scan_source_code(source) if f.rule_id == "CG-030"]

    assert lines(CACHE) == [7]
    head, body = CACHE.split("    if key")
    assert not lines(head + "    async with cache_lock:\n" + indent("    if key" + body, "    "))
    assert lines(
        CACHE.replace(
            "        CACHE[key]", "        async with cache_lock:\n            CACHE[key]"
        )
    ) == [8]
    assert lines(
        "class App:\n    count = 0\n    async def tick(self):\n        n = self.count\n        await wait()\n        App.count += n"
    ) == [6]


def order(a: str, b: str) -> str:
    return f"async def act(session):\n    await session.scalar(select({a}).with_for_update())\n    await session.scalar(select({b}).with_for_update())\n"


def test_cli_cycle_and_reports(tmp_path: Path) -> None:
    runner = CliRunner()
    a, b = tmp_path / "service_a.py", tmp_path / "service_b.py"
    a.write_text(order("Wallet", "Ledger"))
    b.write_text(order("Ledger", "Wallet"))
    (tmp_path / "updates.py").write_text(CACHE + BRANCH)

    def scan(jobs: str) -> list[tuple[str, str]]:
        result = runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--format",
                "sarif",
                "--jobs",
                jobs,
                "--cache-dir",
                str(tmp_path / ".cache"),
            ],
        )
        assert result.exit_code == 1, result.output
        run = json.loads(result.stdout)["runs"][0]
        return [(r["ruleId"], r["message"]["text"]) for r in run["results"]]

    first = scan("1")
    assert first == scan("2")
    assert {"CG-028", "CG-029", "CG-030"} <= {rid for rid, _ in first}
    (trace,) = [msg for rid, msg in first if rid == "CG-029"]
    assert "service_b.py:3 (Ledger -> Wallet) <-> service_a.py:3 (Wallet -> Ledger)" in trace
    report = tmp_path / "report.html"
    result = runner.invoke(
        app, ["report", str(tmp_path), "--format", "html", "--output", str(report)]
    )
    assert result.exit_code == 0
    assert all(label in report.read_text() for label in ["CG-028", "CG-029", "CG-030", "CWE-833"])
    b.write_text(order("Wallet", "Ledger"))
    assert not any(rid == "CG-029" for rid, _ in scan("2"))


def test_three_resources_and_released_locks(tmp_path: Path) -> None:
    from concurrency_guard.engine import scan_directory_parallel

    (tmp_path / "locks.py").write_text(
        "import asyncio\na_lock = asyncio.Lock()\nb_lock = asyncio.Lock()\nc_lock = asyncio.Lock()\n"
    )

    def source(a: str, b: str, nested: bool) -> str:
        body = f"async with {b}:\n    pass"
        return f"from locks import {a}, {b}\nasync def work():\n    async with {a}:\n" + (
            indent(body, "        ") if nested else "        pass\n" + indent(body, "    ")
        )

    for a, b in [("a_lock", "b_lock"), ("b_lock", "c_lock"), ("c_lock", "a_lock")]:
        (tmp_path / f"{a}.py").write_text(source(a, b, True))
    cycles = [f for f in scan_directory_parallel(tmp_path) if f.rule_id == "CG-029"]
    assert len(cycles) == 1
    assert cycles[0].message.count(" <-> ") == 2
    (tmp_path / "b_lock.py").write_text(source("b_lock", "c_lock", False))
    assert not any(f.rule_id == "CG-029" for f in scan_directory_parallel(tmp_path))


def test_failed_acquisition_and_released_row_lock() -> None:
    src = """async def update(session):
    wallet = await session.get(Wallet, 1)
    try:
        wallet = await session.scalar(select(Wallet).with_for_update())
    except Busy:
        wallet.amount += 1
    await session.commit()
"""
    assert [(f.rule_id, f.lineno) for f in scan_source_code(src) if f.rule_id == "CG-028"] == [
        ("CG-028", 6)
    ]
    released = """async def update(session):
    wallet = await session.scalar(select(Wallet).with_for_update())
    await session.commit()
    wallet.amount += 1
    await session.commit()
"""
    assert any(f.rule_id == "CG-001" for f in scan_source_code(released))

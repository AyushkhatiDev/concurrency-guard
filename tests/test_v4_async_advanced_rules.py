"""Regression coverage for async rule detection and cancellation rewriting."""

from pathlib import Path

import pytest

from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.scanner.ast_rules import scan_directory, scan_source_code


@pytest.mark.parametrize("body", [
    "await asyncio.gather(load(db), save(session=db))",
    "async with asyncio.TaskGroup() as group:\n        group.create_task(load(db))\n        group.create_task(save(db))",
])
def test_concurrent_session_sharing(body: str) -> None:
    source = f"import asyncio\nasync def run(db: AsyncSession):\n    {body}\n"
    assert [f.rule_id for f in scan_source_code(source)].count("CG-031") == 1
    assert not any(f.rule_id == "CG-031" for f in scan_source_code(source.replace("save(", "save_new(").replace("save_new(db)", "save_new(other)").replace("session=db", "session=other")))


def test_nested_and_helper_async_locks(tmp_path: Path) -> None:
    (tmp_path / "locks.py").write_text("import asyncio\nlock = asyncio.Lock()\n")
    (tmp_path / "helper.py").write_text("from locks import lock\nasync def take():\n    async with lock:\n        pass\n")
    caller = """from locks import lock
from helper import take
async def run():
    async with lock:
        await take()
        async with lock:
            pass
"""
    (tmp_path / "caller.py").write_text(caller)
    findings = [f for f in scan_directory(tmp_path) if f.rule_id == "CG-032"]
    assert [f.lineno for f in findings] == [5, 6]
    assert not any(f.rule_id == "CG-032" for f in scan_source_code(caller.replace("        async with lock:", "        async with other_lock:")))


@pytest.mark.parametrize("header", ["except:", "except BaseException:"])
def test_cancellation_detection_and_fixer_round_trip(header: str) -> None:
    source = f"""async def run():
    try:
        await work()
    {header}
        return
"""
    assert any(f.rule_id == "CG-033" for f in scan_source_code(source))
    fixed = apply_all_fixes(source, rules={"CG-033"})
    assert "except asyncio.CancelledError:\n        raise" in fixed
    assert not any(f.rule_id == "CG-033" for f in scan_source_code(fixed))
    assert fixed == apply_all_fixes(fixed, rules={"CG-033"})
    reraised = source.replace("        return", "        raise")
    assert not any(f.rule_id == "CG-033" for f in scan_source_code(reraised))

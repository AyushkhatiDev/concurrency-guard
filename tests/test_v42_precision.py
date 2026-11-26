import ast

import libcst as cst
import pytest

from concurrency_guard import cfg
from concurrency_guard.patcher import cst_fixer
from concurrency_guard.scanner.ast_rules import scan_source_code


@pytest.mark.parametrize("factory", [False, True])
def test_session_origin_and_branch_overlap(factory: bool) -> None:
    origin = "unit = make()" if factory else "unit = incoming"
    source = f"""from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession as Session
make = async_sessionmaker(engine)
async def run(incoming: Session, flag):
    {origin}
    alias = unit
    async with asyncio.TaskGroup() as tg:
        if flag:
            tg.create_task(load(alias))
        else:
            tg.create_task(save(unit))
"""
    assert not any(f.rule_id == "CG-031" for f in scan_source_code(source))
    findings = scan_source_code(source + "        tg.create_task(refresh(unit))\n")
    finding, = (f for f in findings if f.rule_id == "CG-031")
    assert [s.line for s in finding.evidence] == [4 if factory else 3, 8, 11]


@pytest.mark.parametrize(("handler", "swallows"), [
    ("await cleanup()\n        raise err", False),
    ("if flag:\n            return\n        raise", True),
    ("try:\n            await cleanup()\n        finally:\n            raise", False),
    ("await cleanup()", True),
    ("if False:\n            return\n        raise", False),
])
def test_explicit_cancellation(handler: str, swallows: bool) -> None:
    source = ("from asyncio import CancelledError\nasync def run(flag):\n    try:\n        await work()\n"
              f"    except CancelledError as err:\n        {handler}\n")
    assert any(f.rule_id == "CG-033" for f in scan_source_code(source)) == swallows
    assert cst_fixer.apply_all_fixes(source, rules={"CG-033"}) == source


def test_ineffective_patch_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def noop(self: object, original_node: cst.Try, updated_node: cst.Try) -> cst.Try:
        return updated_node

    monkeypatch.setattr(cst_fixer.CancelledErrorReraiseTransformer, "leave_Try", noop)
    source = "async def run():\n    try: await work()\n    except BaseException: pass\n"
    result = cst_fixer.apply_all_fixes_with_report(source, rules={"CG-033"})
    assert result.code == source
    assert any("remains" in skip.reason for skip in result.skipped)


def test_cfg_state_overflow_discards_incomplete_lock_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cfg, "MAX_LOCK_STATES", 2)
    function = ast.parse("def run(x):\n    if x:\n        a = True\n    else:\n        a = False\n    return a").body[0]
    assert isinstance(function, ast.FunctionDef)
    graph = cfg.build_function_cfg(function)
    assert cfg.lock_states(graph) == {}
    assert "Partial analysis of run" in graph.warnings[0]


def test_manual_and_fixable_handlers_in_same_function() -> None:
    source = """async def run():
    try: await first()
    except BaseException: pass
    try: await second()
    except asyncio.CancelledError:
        await cleanup()
"""
    fixed = cst_fixer.apply_all_fixes(source, rules={"CG-033"})
    assert fixed != source
    assert fixed.endswith("except asyncio.CancelledError:\n        await cleanup()\n")
    assert len([f for f in scan_source_code(fixed) if f.rule_id == "CG-033"]) == 1

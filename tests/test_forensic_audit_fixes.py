"""Focused regressions for the v2.4.1 forensic audit fixes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.runner.runtime_verifier import load_function, verify_function
from concurrency_guard.scanner.ast_rules import scan_source_code
from concurrency_guard.scanner.call_graph import build_call_graph
from concurrency_guard.scanner.suppression import parse_rules
from concurrency_guard.scanner.taint_tracker import find_tainted_shared_state_mutations


def test_relative_package_target_loads(tmp_path: Path) -> None:
    package = tmp_path / "pkg"; package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "models.py").write_text("VALUE = 1\n")
    target = package / "worker.py"; target.write_text("from .models import VALUE\ndef run(): return VALUE\n")
    _, function = load_function(target, "run")
    assert function() == 1


def test_mixed_path_call_graph_is_safe(tmp_path: Path) -> None:
    source = tmp_path / "x.py"; source.write_text("def f(): pass\n")
    assert build_call_graph([source], roots=[Path(".")]).functions


def test_cache_flag_and_sarif_are_available(tmp_path: Path) -> None:
    source = tmp_path / "x.py"; source.write_text("x = 1\n")
    result = CliRunner().invoke(app, ["scan", str(source), "--cache", "--format", "sarif"])
    assert result.exit_code == 0 and json.loads(result.stdout)["version"] == "2.1.0"


def test_suppressed_finding_is_not_patched() -> None:
    source = "cache = {}\nasync def f(k):  # cg:ignore[CG-006]\n    value = cache[k]\n    await wait()\n    cache[k] = value\n"
    assert "_cguard_async_lock" not in apply_all_fixes(source, {"CG-006"})


def test_async_django_manager_and_asave_are_detected() -> None:
    source = "async def f():\n    user = await User.active_objects.aget(id=1)\n    user.x = 2\n    await user.asave()\n"
    assert any(f.rule_id == "CG-016" for f in scan_source_code(source))


def test_class_method_taint_and_keyword_transfer(tmp_path: Path) -> None:
    source = tmp_path / "a.py"
    source.write_text("state = {}\nclass Service:\n async def put(self, data):\n  data['x'] = 1\nasync def run():\n await Service().put(data=state)\n")
    graph = build_call_graph([source], roots=[tmp_path])
    assert find_tainted_shared_state_mutations([source], graph)


@pytest.mark.parametrize("delta", [-50, 10, 1])
def test_headless_uses_measured_delta(tmp_path: Path, delta: int) -> None:
    target = tmp_path / "target.py"
    target.write_text(f"state = {{'count': 100}}\ndef change():\n    state['count'] += ({delta})\n")
    result = verify_function(target, "change", workers=2)
    assert result["expected_value"] == 100 + (delta * result["completed_workers"])


@pytest.mark.parametrize("raw, expected", [
    (None, {"*"}), ("", {"*"}), ("CG-001", {"CG-001"}),
    ("CG-001, CG-002", {"CG-001", "CG-002"}), ("cg-006", {"CG-006"}),
    ("  CG-014 ", {"CG-014"}), ("CG-015,", {"CG-015"}),
    ("*,CG-001", {"*", "CG-001"}), ("CG-016", {"CG-016"}),
    ("CG-003,CG-008", {"CG-003", "CG-008"}), ("CG-007", {"CG-007"}),
])
def test_suppression_rule_parser_is_deterministic(raw: str | None, expected: set[str]) -> None:
    assert parse_rules(raw) == expected


def test_sync_class_rmw_heuristic_and_concurrency_detection() -> None:
    # 1. Synchronous AST/CST class mutating self.depth += 1 / -= 1 or doing RMW
    # even with 'atomic' or 'lock' in identifiers must produce 0 CG-008 findings.
    sync_transformer = """
class CSTAtomicDepthTransformer:
    def __init__(self):
        self.atomic_depth = 0
        self.lock_count = 0
    def visit_With(self, node):
        self.atomic_depth += 1
        d = self.lock_count
        self.lock_count = d + 1
    def leave_With(self, node):
        self.atomic_depth -= 1
        d = self.lock_count
        self.lock_count = d - 1
"""
    sync_findings = [f for f in scan_source_code(sync_transformer) if f.rule_id == "CG-008"]
    assert len(sync_findings) == 0

    # 2. Synchronous LibCST transformer modifying local list elements (like cst_fixer.py)
    # must produce 0 CG-008 findings.
    sync_list_mod = """
class IdempotencyHeaderTransformer:
    def leave_FunctionDef(self, original_node, updated_node):
        old_params = list(updated_node.params.params)
        if old_params:
            last = old_params[-1]
            old_params[-1] = last.with_changes(comma=None)
"""
    list_findings = [f for f in scan_source_code(sync_list_mod) if f.rule_id == "CG-008"]
    assert len(list_findings) == 0

    # 3. Explicitly verified multi-threaded target executing RMW must trigger CG-008.
    threaded_target = """
import threading
state = {}
def worker():
    val = state['count']
    state['count'] = val + 1
t = threading.Thread(target=worker)
"""
    threaded_findings = [f for f in scan_source_code(threaded_target) if f.rule_id == "CG-008"]
    assert len(threaded_findings) == 1
    assert threaded_findings[0].rule_id == "CG-008"

    # 4. Async coroutine with intervening await suspension point must trigger CG-008.
    async_with_await = """
import asyncio
state = {}
async def async_worker():
    val = state['count']
    await asyncio.sleep(0.01)
    state['count'] = val + 1
"""
    async_findings = [f for f in scan_source_code(async_with_await) if f.rule_id == "CG-008"]
    assert len(async_findings) == 1
    assert async_findings[0].rule_id == "CG-008"

    # 5. Async coroutine WITHOUT intervening await suspension point must NOT trigger CG-008.
    async_without_await = """
state = {}
async def safe_async_worker():
    val = state['count']
    state['count'] = val + 1
"""
    safe_async_findings = [f for f in scan_source_code(async_without_await) if f.rule_id == "CG-008"]
    assert len(safe_async_findings) == 0


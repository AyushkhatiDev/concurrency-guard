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

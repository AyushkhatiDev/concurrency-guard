"""Regression coverage for shared-state semantic taint flow."""

from __future__ import annotations

from pathlib import Path

from concurrency_guard.scanner.ast_rules import scan_directory, scan_source_code


def test_detects_global_dict_after_two_local_reference_reassignments() -> None:
    """A shared dictionary remains tainted through local aliases in an async endpoint."""
    code = """
shared_cache = {}

async def update_cache(key, value):
    first_ref = shared_cache
    local_ref = first_ref
    local_ref[key] = value
"""
    findings = [finding for finding in scan_source_code(code) if finding.rule_id == "CG-015"]
    assert len(findings) == 1
    assert findings[0].function_name == "update_cache"
    assert findings[0].lineno == 7
    assert "local variable referencing shared state" in findings[0].message


def test_propagates_taint_to_resolved_callee_parameter(tmp_path: Path) -> None:
    """A graph-resolved local call transfers taint from an alias to its callee."""
    (tmp_path / "worker.py").write_text(
        "async def mutate(mapping):\n    mapping['count'] = 1\n",
        encoding="utf-8",
    )
    (tmp_path / "route.py").write_text(
        "from worker import mutate\n\nshared = {}\n\nasync def endpoint():\n    alias = shared\n    await mutate(alias)\n",
        encoding="utf-8",
    )
    findings = [finding for finding in scan_directory(tmp_path) if finding.rule_id == "CG-015"]
    assert [(finding.function_name, finding.lineno) for finding in findings] == [("mutate", 2)]

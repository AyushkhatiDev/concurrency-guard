"""Cross-file call graph and inter-procedural shared-state regression tests."""

from __future__ import annotations

from pathlib import Path

from concurrency_guard.scanner.ast_rules import scan_directory
from concurrency_guard.scanner.call_graph import build_call_graph


def test_follows_three_module_import_chain_to_shared_state_mutation(tmp_path: Path) -> None:
    """A route must inherit the race risk of a transitive shared-state callee."""
    (tmp_path / "state.py").write_text(
        "balances = {}\n\ndef deduct(user):\n    balances[user] = balances.get(user, 0) - 1\n",
        encoding="utf-8",
    )
    (tmp_path / "checkout.py").write_text(
        "from state import deduct\n\ndef process_checkout(user):\n    deduct(user)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from checkout import process_checkout\n\nasync def checkout(user):\n    process_checkout(user)\n",
        encoding="utf-8",
    )

    findings = [finding for finding in scan_directory(tmp_path) if finding.rule_id == "CG-014"]
    assert {finding.function_name for finding in findings} == {"process_checkout", "checkout"}
    assert all("state.deduct" in finding.message for finding in findings)


def test_graph_resolves_import_aliases_without_importing_user_code(tmp_path: Path) -> None:
    """Alias resolution is source based, and recognizes only supplied local functions."""
    worker = tmp_path / "worker.py"
    worker.write_text("def mutate():\n    pass\n", encoding="utf-8")
    caller = tmp_path / "caller.py"
    caller.write_text("from worker import mutate as update\n\ndef entry():\n    update()\n", encoding="utf-8")

    graph = build_call_graph([worker, caller], roots=[tmp_path])
    assert graph.edges["caller.entry"] == {"worker.mutate"}

"""SARIF 2.1.0 serialization for GitHub and enterprise code-scanning tools."""

from __future__ import annotations

from typing import Any

from concurrency_guard import __version__
from concurrency_guard.scanner.ast_rules import ASTFinding


def findings_to_sarif(findings: list[ASTFinding]) -> dict[str, Any]:
    """Return a standards-shaped SARIF log without requiring an external SDK."""
    rule_ids = [f"CG-{number:03d}" for number in range(1, 17)]
    rules = [{"id": rule_id, "name": rule_id, "shortDescription": {"text": "Concurrency Guard rule"}} for rule_id in rule_ids]
    results = [{
        "ruleId": finding.rule_id,
        "level": "error",
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.filename}, "region": {"startLine": finding.lineno, "startColumn": 1}}}],
        "fixes": [{"description": {"text": finding.suggested_fix_hint}}],
    } for finding in findings]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "concurrency-guard", "version": __version__, "rules": rules}}, "results": results}]}

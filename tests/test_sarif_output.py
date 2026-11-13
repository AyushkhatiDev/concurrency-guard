"""OASIS SARIF v2.1.0 schema compliance, fingerprinting, and CLI export tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.sarif import (
    RULE_REGISTRY,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_NAME,
    compute_primary_location_hash,
    findings_to_sarif,
    normalize_sarif_uri,
    serialize_sarif,
)
from concurrency_guard.scanner.ast_rules import ASTFinding

runner = CliRunner()


def test_sarif_top_level_schema_structure() -> None:
    """SARIF output conforms to OASIS SARIF v2.1.0 schema with driver metadata."""
    finding = ASTFinding(
        rule_id="CG-001",
        filename="src/routers/checkout.py",
        lineno=42,
        function_name="checkout",
        message="Unlocked Read-Modify-Write Race Condition",
        suggested_fix_hint="Add .with_for_update() to the select query.",
        confidence="HIGH",
        end_lineno=45,
        col_offset=4,
    )

    doc = findings_to_sarif([finding])

    assert doc["$schema"] == SARIF_SCHEMA_URI
    assert doc["version"] == SARIF_VERSION
    assert "runs" in doc and len(doc["runs"]) == 1

    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == TOOL_NAME
    assert bool(driver["semanticVersion"])
    assert driver["informationUri"] == "https://concurrencyguard.dev"
    assert isinstance(driver["rules"], list)
    assert len(driver["rules"]) >= 10


def test_sarif_rules_metadata_mapping() -> None:
    """Rules CG-001 through CG-010 contain complete CWE-362 metadata and severity."""
    for i in range(1, 11):
        rule_id = f"CG-{i:03d}"
        assert rule_id in RULE_REGISTRY, f"Missing rule {rule_id} in registry"
        meta = RULE_REGISTRY[rule_id]

        assert meta["id"] == rule_id
        assert isinstance(meta["name"], str) and len(meta["name"]) > 0
        assert "text" in meta["shortDescription"]
        assert "text" in meta["fullDescription"]
        assert meta["helpUri"] == f"https://concurrencyguard.dev/rules/{rule_id}"

        level = meta["defaultConfiguration"]["level"]
        assert level in {"error", "warning"}

        tags = meta["properties"]["tags"]
        assert isinstance(tags, list)
        assert any("concurrency" in t or "race-condition" in t or "cwe-362" in t for t in tags)


def test_sarif_region_coordinates_and_posix_paths(tmp_path: Path) -> None:
    """Coordinates are 1-based and paths are normalized to POSIX forward slashes."""
    finding = ASTFinding(
        rule_id="CG-001",
        filename="services\\billing\\wallet.py",  # Windows-style backslashes
        lineno=15,
        function_name="deduct",
        message="RMW Race",
        suggested_fix_hint="with_for_update()",
        confidence="HIGH",
        end_lineno=18,
        col_offset=8,  # 0-based col_offset 8 -> 1-based startColumn 9
    )

    doc = findings_to_sarif([finding], workspace_root=tmp_path)
    result = doc["runs"][0]["results"][0]

    # Verify POSIX normalization
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri
    assert uri == "services/billing/wallet.py"

    # Verify 1-based coordinates
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 15
    assert region["startColumn"] == 9
    assert region["endLine"] == 18
    assert region["endColumn"] == 10


def test_normalize_sarif_uri_edge_cases(tmp_path: Path) -> None:
    """normalize_sarif_uri handles absolute, relative, and Windows-style paths."""
    # Windows-style path
    assert normalize_sarif_uri("foo\\bar\\baz.py") == "foo/bar/baz.py"

    # Redundant ./
    assert normalize_sarif_uri("./src/app.py") == "src/app.py"

    # Absolute path under workspace_root
    abs_file = tmp_path / "sub" / "module.py"
    assert normalize_sarif_uri(str(abs_file), workspace_root=tmp_path) == "sub/module.py"


def test_sarif_zero_findings_produces_empty_results() -> None:
    """Zero-finding scans produce a valid SARIF log with results: []."""
    doc = findings_to_sarif([])

    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) >= 10


def test_sarif_deterministic_fingerprints() -> None:
    """partialFingerprints.primaryLocationLineHash is stable across repeated calls."""
    hash1 = compute_primary_location_hash("CG-001", "src/wallet.py", 42, "Unlocked RMW")
    hash2 = compute_primary_location_hash("CG-001", "src/wallet.py", 42, "Unlocked RMW")
    hash3 = compute_primary_location_hash("CG-001", "src/wallet.py", 43, "Unlocked RMW")

    assert isinstance(hash1, str) and len(hash1) == 64
    assert hash1 == hash2
    assert hash1 != hash3


def test_sarif_fixes_remediation_guidance() -> None:
    """Remediation hints are mapped to SARIF fixes array."""
    finding_with_fix = ASTFinding(
        rule_id="CG-001",
        filename="app.py",
        lineno=1,
        function_name="f",
        message="msg",
        suggested_fix_hint="Use select(...).with_for_update()",
    )
    doc = findings_to_sarif([finding_with_fix])
    result = doc["runs"][0]["results"][0]
    assert "fixes" in result
    assert result["fixes"][0]["description"]["text"] == "Use select(...).with_for_update()"

    finding_no_fix = ASTFinding(
        rule_id="CG-001",
        filename="app.py",
        lineno=1,
        function_name="f",
        message="msg",
        suggested_fix_hint="",
    )
    doc_no_fix = findings_to_sarif([finding_no_fix])
    assert "fixes" not in doc_no_fix["runs"][0]["results"][0]


def test_cli_format_sarif_stdout() -> None:
    """cguard scan --format sarif emits pure valid JSON without ANSI color codes."""
    res = runner.invoke(app, ["scan", "examples/real_world_ecommerce", "--format", "sarif", "--no-cache"])
    assert res.exit_code == 1

    parsed = json.loads(res.stdout)
    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"][0]["results"]) >= 5


def test_cli_format_sarif_output_file(tmp_path: Path) -> None:
    """cguard scan --format sarif --output path/to/file writes clean UTF-8 SARIF."""
    output_file = tmp_path / "artifacts" / "scan_report.sarif"
    res = runner.invoke(
        app,
        [
            "scan",
            "examples/real_world_ecommerce",
            "--format",
            "sarif",
            "--output",
            str(output_file),
            "--no-cache",
        ],
    )
    assert res.exit_code == 1
    assert output_file.exists()

    raw_content = output_file.read_text(encoding="utf-8")
    parsed = json.loads(raw_content)

    assert parsed["$schema"] == SARIF_SCHEMA_URI
    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"][0]["results"]) >= 5

    # File must not contain ANSI escape sequences
    assert "\x1b[" not in raw_content


def test_serialize_sarif_is_deterministic() -> None:
    """serialize_sarif produces deterministic, byte-identical JSON strings."""
    findings = [
        ASTFinding(
            rule_id="CG-002",
            filename="routes/api.py",
            lineno=20,
            function_name="submit",
            message="Missing Idempotency Guard",
            suggested_fix_hint="Add idempotency key",
        ),
        ASTFinding(
            rule_id="CG-001",
            filename="routes/api.py",
            lineno=10,
            function_name="checkout",
            message="Unlocked RMW",
            suggested_fix_hint="with_for_update()",
        ),
    ]

    s1 = serialize_sarif(findings)
    s2 = serialize_sarif(findings)
    assert s1 == s2

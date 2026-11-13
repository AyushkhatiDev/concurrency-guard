"""cguard.sarif alias for concurrency_guard.sarif."""

from concurrency_guard.sarif import (
    RULE_REGISTRY,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_INFO_URI,
    TOOL_NAME,
    compute_primary_location_hash,
    findings_to_sarif,
    get_rule_metadata,
    map_confidence_to_level,
    normalize_sarif_uri,
    serialize_sarif,
)

__all__ = [
    "RULE_REGISTRY",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "TOOL_INFO_URI",
    "TOOL_NAME",
    "compute_primary_location_hash",
    "findings_to_sarif",
    "get_rule_metadata",
    "map_confidence_to_level",
    "normalize_sarif_uri",
    "serialize_sarif",
]

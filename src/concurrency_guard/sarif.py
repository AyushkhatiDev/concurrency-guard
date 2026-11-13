"""OASIS SARIF v2.1.0 serializer and rule metadata registry for GitHub Code Scanning."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

from concurrency_guard import __version__

if TYPE_CHECKING:
    from concurrency_guard.scanner.ast_rules import ASTFinding

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "ConcurrencyGuard"
TOOL_INFO_URI = "https://concurrencyguard.dev"

# Comprehensive CWE-362 Concurrency & Race-Condition Rule Registry (CG-001 through CG-021)
RULE_REGISTRY: dict[str, dict[str, Any]] = {
    "CG-001": {
        "id": "CG-001",
        "name": "UnlockedReadModifyWriteRace",
        "shortDescription": {"text": "Unlocked Read-Modify-Write Race Condition"},
        "fullDescription": {
            "text": (
                "A database record is retrieved via select() or db.get(), mutated in memory, "
                "and committed without row-level locking (with_for_update), allowing concurrent "
                "requests to overwrite state and cause lost updates."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-001",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "cwe-362", "database", "sqlalchemy"],
            "precision": "high",
            "security-severity": "8.5",
        },
    },
    "CG-002": {
        "id": "CG-002",
        "name": "MissingIdempotencyGuard",
        "shortDescription": {"text": "Missing Idempotency Guard on Mutating POST Route"},
        "fullDescription": {
            "text": (
                "A mutating HTTP POST route performs database writes or credit transfers without "
                "an Idempotency-Key header check, risking duplicate financial operations on client retry."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-002",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "idempotency", "cwe-362", "fastapi"],
            "precision": "high",
            "security-severity": "7.5",
        },
    },
    "CG-003": {
        "id": "CG-003",
        "name": "AsyncLoopQueryExplosion",
        "shortDescription": {"text": "Async Loop N+1 Query Explosion"},
        "fullDescription": {
            "text": (
                "Database queries executed iteratively inside async loops exhaust connection pool "
                "capacity and cause severe latency spikes under concurrent loads."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-003",
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["performance", "concurrency", "async", "database", "cwe-400"],
            "precision": "high",
            "security-severity": "5.0",
        },
    },
    "CG-004": {
        "id": "CG-004",
        "name": "CheckThenActUniquenessRace",
        "shortDescription": {"text": "Check-Then-Act Uniqueness Race Condition"},
        "fullDescription": {
            "text": (
                "Checking for record existence before an insert without database unique constraints "
                "or IntegrityError transaction recovery creates a race window permitting duplicates."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-004",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "cwe-362", "database"],
            "precision": "high",
            "security-severity": "7.0",
        },
    },
    "CG-005": {
        "id": "CG-005",
        "name": "NonIdempotentCeleryRetry",
        "shortDescription": {"text": "Non-Idempotent Celery Retry Task"},
        "fullDescription": {
            "text": (
                "A retrying Celery task lacks late acknowledgment (acks_late=True) or distributed "
                "locking, causing duplicated execution of uncommitted work on worker crash."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-005",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["reliability", "concurrency", "celery", "idempotency", "cwe-362"],
            "precision": "high",
            "security-severity": "7.0",
        },
    },
    "CG-006": {
        "id": "CG-006",
        "name": "AsyncSharedStateMutation",
        "shortDescription": {"text": "Unsynchronized Async Shared-State Mutation"},
        "fullDescription": {
            "text": (
                "Coroutines mutating module-level collections outside an active async with lock: "
                "context risk corrupted collection internals and lost updates."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-006",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "async", "cwe-362"],
            "precision": "high",
            "security-severity": "7.5",
        },
    },
    "CG-007": {
        "id": "CG-007",
        "name": "ThreadedCollectionMutation",
        "shortDescription": {"text": "Threaded Collection Mutation Without Lock"},
        "fullDescription": {
            "text": (
                "Functions spawned via threading.Thread mutate shared collections without synchronization, "
                "causing non-deterministic memory races."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-007",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "threading", "cwe-362"],
            "precision": "high",
            "security-severity": "7.5",
        },
    },
    "CG-008": {
        "id": "CG-008",
        "name": "GenericInMemoryRMWRace",
        "shortDescription": {"text": "Generic In-Memory Read-Modify-Write Race"},
        "fullDescription": {
            "text": (
                "Shared state is read, modified via in-place arithmetic or reassignment, and stored "
                "without synchronization boundaries."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-008",
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["concurrency", "race-condition", "cwe-362"],
            "precision": "medium",
            "security-severity": "6.0",
        },
    },
    "CG-009": {
        "id": "CG-009",
        "name": "ConcurrentFileOverwriteRace",
        "shortDescription": {"text": "Concurrent File Overwrite Race"},
        "fullDescription": {
            "text": (
                "Multiple worker processes writing to the same filesystem path without file locks "
                "risk truncated or corrupted files."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-009",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "filesystem", "cwe-362"],
            "precision": "high",
            "security-severity": "6.5",
        },
    },
    "CG-010": {
        "id": "CG-010",
        "name": "PredictableTempfileCollision",
        "shortDescription": {"text": "Predictable Temporary File Collision"},
        "fullDescription": {
            "text": (
                "Using fixed or predictable filenames in shared temporary directories opens symlink "
                "and collision race attack vectors (CWE-377)."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-010",
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["security", "concurrency", "tempfile", "cwe-377", "cwe-362"],
            "precision": "medium",
            "security-severity": "5.5",
        },
    },
    "CG-011": {
        "id": "CG-011",
        "name": "RedisCheckThenActRace",
        "shortDescription": {"text": "Redis Check-Then-Act Race Condition"},
        "fullDescription": {
            "text": (
                "Non-atomic Redis get followed by set without transactions or Lua scripts allows "
                "concurrent requests to override state non-atomically."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-011",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "redis", "race-condition", "cwe-362"],
            "precision": "high",
            "security-severity": "7.5",
        },
    },
    "CG-012": {
        "id": "CG-012",
        "name": "NonAtomicCacheInvalidation",
        "shortDescription": {"text": "Non-Atomic Cache Invalidation"},
        "fullDescription": {
            "text": (
                "Database updates executed without atomic cache eviction cause race conditions where "
                "stale cached values overwrite fresh database state."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-012",
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["concurrency", "cache", "cwe-362"],
            "precision": "medium",
            "security-severity": "5.0",
        },
    },
    "CG-013": {
        "id": "CG-013",
        "name": "LockOrderInversionDeadlock",
        "shortDescription": {"text": "Potential Deterministic Lock-Order Deadlock"},
        "fullDescription": {
            "text": (
                "Nested locks acquired in conflicting order across execution paths lead to "
                "deterministic deadlock when routines execute concurrently."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-013",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["concurrency", "deadlock", "threading", "cwe-833"],
            "precision": "high",
            "security-severity": "7.5",
        },
    },
    "CG-014": {
        "id": "CG-014",
        "name": "InterProceduralCallChainRace",
        "shortDescription": {"text": "Inter-Procedural Shared-State Call-Chain Race"},
        "fullDescription": {
            "text": (
                "Public entry point calls a function whose transitive call chain reaches an "
                "unguarded shared-state mutation across module boundaries."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-014",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "inter-procedural", "cwe-362"],
            "precision": "high",
            "security-severity": "7.0",
        },
    },
    "CG-015": {
        "id": "CG-015",
        "name": "TaintedSharedStateMutation",
        "shortDescription": {"text": "Tainted Shared State Mutation"},
        "fullDescription": {
            "text": (
                "A local variable referencing shared state is mutated without concurrency controls."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-015",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "taint", "cwe-362"],
            "precision": "high",
            "security-severity": "7.0",
        },
    },
    "CG-016": {
        "id": "CG-016",
        "name": "DjangoUnlockedReadModifyWrite",
        "shortDescription": {"text": "Django ORM Unlocked Read-Modify-Write Race"},
        "fullDescription": {
            "text": (
                "Django model fetched via objects.get() is mutated and saved without "
                "select_for_update() inside transaction.atomic(), causing lost updates."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-016",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "django", "cwe-362"],
            "precision": "high",
            "security-severity": "8.0",
        },
    },
    "CG-017": {
        "id": "CG-017",
        "name": "DjangoAtomicFExpressionOptimization",
        "shortDescription": {"text": "Django Non-Atomic Arithmetic on Model Field"},
        "fullDescription": {
            "text": (
                "In-memory arithmetic on Django model field before save() can lose concurrent updates; "
                "use atomic F() expressions instead."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-017",
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["concurrency", "django", "f-expression", "cwe-362"],
            "precision": "high",
            "security-severity": "6.0",
        },
    },
    "CG-018": {
        "id": "CG-018",
        "name": "DistributedLockUnsafeRelease",
        "shortDescription": {"text": "Distributed Lock Unsafe Release"},
        "fullDescription": {
            "text": (
                "Releasing a distributed Redis lock via raw delete() can release another worker's lock "
                "if the original lock expired; use a Lua script verifying token ownership."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-018",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "redis", "distributed-lock", "cwe-362"],
            "precision": "high",
            "security-severity": "7.5",
        },
    },
    "CG-019": {
        "id": "CG-019",
        "name": "FastAPISessionLeakToBackgroundTask",
        "shortDescription": {"text": "FastAPI DB Session Leak to Background Task"},
        "fullDescription": {
            "text": (
                "Request-scoped database session passed to FastAPI BackgroundTasks outlives the "
                "HTTP request lifecycle, causing use-after-free or concurrent connection errors."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-019",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["concurrency", "fastapi", "session-leak", "cwe-362"],
            "precision": "high",
            "security-severity": "7.0",
        },
    },
    "CG-020": {
        "id": "CG-020",
        "name": "UnboundedLockAcrossNetworkIO",
        "shortDescription": {"text": "Unbounded Lock Held Across Network I/O"},
        "fullDescription": {
            "text": (
                "Holding a concurrency lock or open transaction during outbound HTTP/network I/O "
                "causes connection starvation and cascading thread exhaustion."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-020",
        "defaultConfiguration": {"level": "warning"},
        "properties": {
            "tags": ["concurrency", "performance", "lock-contention", "cwe-400"],
            "precision": "medium",
            "security-severity": "5.5",
        },
    },
    "CG-021": {
        "id": "CG-021",
        "name": "GeneratorLockLeak",
        "shortDescription": {"text": "Generator Lock Leak Across Yield"},
        "fullDescription": {
            "text": (
                "Yielding values inside a with lock: context manager suspends generator execution "
                "while leaving the lock held indefinitely across external consumer iterations."
            )
        },
        "helpUri": "https://concurrencyguard.dev/rules/CG-021",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["concurrency", "generator", "deadlock", "cwe-833", "cwe-362"],
            "precision": "high",
            "security-severity": "7.5",
        },
    },
}


def normalize_sarif_uri(filename: str, workspace_root: Optional[Union[Path, str]] = None) -> str:
    """Normalize a file path to a POSIX-compliant URI relative to the workspace root.

    Handles Windows backslashes, absolute paths, and relative paths deterministically.
    """
    clean_str = filename.replace("\\", "/")
    path_obj = Path(clean_str)

    if workspace_root is not None:
        try:
            root_path = Path(workspace_root).resolve()
            if path_obj.is_absolute():
                rel = path_obj.resolve().relative_to(root_path)
                return rel.as_posix()
            # If path_obj is relative, check if resolving against root makes sense
            resolved = (root_path / path_obj).resolve()
            rel = resolved.relative_to(root_path)
            return rel.as_posix()
        except (ValueError, OSError):
            pass

    if path_obj.is_absolute():
        try:
            cwd = Path.cwd().resolve()
            rel = path_obj.resolve().relative_to(cwd)
            return rel.as_posix()
        except (ValueError, OSError):
            pass

    # Clean up redundant ./ or slashes
    posix_str = path_obj.as_posix().removeprefix("./")
    return posix_str.lstrip("/") if path_obj.is_absolute() else posix_str


def compute_primary_location_hash(rule_id: str, uri: str, start_line: int, message: str) -> str:
    """Compute stable SHA-256 fingerprint for GitHub Code Scanning alert tracking across commits."""
    content = f"{rule_id}:{uri}:{start_line}:{message}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def map_confidence_to_level(confidence: str, rule_id: str) -> str:
    """Map ASTFinding confidence to SARIF result level ('error', 'warning', 'note')."""
    conf = confidence.upper()
    if conf == "HIGH":
        return "error"
    elif conf == "MEDIUM":
        return "warning"
    elif conf == "LOW":
        return "note"

    # Fallback to rule default if confidence string is unexpected
    rule_meta = RULE_REGISTRY.get(rule_id)
    if rule_meta:
        return str(rule_meta.get("defaultConfiguration", {}).get("level", "error"))
    return "error"


def get_rule_metadata(rule_id: str) -> dict[str, Any]:
    """Return spec-compliant SARIF rule definition or generate a fallback for custom rules."""
    if rule_id in RULE_REGISTRY:
        return dict(RULE_REGISTRY[rule_id])

    return {
        "id": rule_id,
        "name": f"CustomRule_{rule_id}",
        "shortDescription": {"text": f"Concurrency Guard custom rule {rule_id}"},
        "fullDescription": {"text": f"Static concurrency verification rule {rule_id}."},
        "helpUri": f"https://concurrencyguard.dev/rules/{rule_id}",
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "tags": ["security", "concurrency", "race-condition", "cwe-362"],
            "precision": "high",
        },
    }


def findings_to_sarif(
    findings: list[ASTFinding],
    workspace_root: Optional[Union[Path, str]] = None,
) -> dict[str, Any]:
    """Convert a list of ASTFinding instances into an OASIS SARIF v2.1.0 compliant log dictionary."""
    # Ensure all active rules are included in the driver rules metadata array
    # Rules list includes built-in registry rules and any custom rule IDs present in findings
    seen_rule_ids: set[str] = set(RULE_REGISTRY.keys())
    for f in findings:
        seen_rule_ids.add(f.rule_id)

    rules_list: list[dict[str, Any]] = [
        get_rule_metadata(rid) for rid in sorted(seen_rule_ids)
    ]

    results: list[dict[str, Any]] = []

    for finding in findings:
        uri = normalize_sarif_uri(finding.filename, workspace_root=workspace_root)
        start_line = max(1, finding.lineno)

        # 1-based start column
        if finding.col_offset is not None and finding.col_offset >= 0:
            start_col = finding.col_offset + 1
        else:
            start_col = 1

        # 1-based end line
        if finding.end_lineno is not None and finding.end_lineno >= start_line:
            end_line = finding.end_lineno
        else:
            end_line = start_line

        end_col = start_col + 1

        level = map_confidence_to_level(finding.confidence, finding.rule_id)
        line_hash = compute_primary_location_hash(finding.rule_id, uri, start_line, finding.message)

        result_obj: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level,
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_col,
                            "endLine": end_line,
                            "endColumn": end_col,
                        },
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": line_hash,
            },
        }

        # Include remediation guidance in fixes if suggested fix hint is available
        if finding.suggested_fix_hint:
            result_obj["fixes"] = [
                {
                    "description": {
                        "text": finding.suggested_fix_hint,
                    }
                }
            ]

        results.append(result_obj)

    # Sort results deterministically by (ruleId, uri, startLine, startColumn)
    results.sort(
        key=lambda r: (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
            r["locations"][0]["physicalLocation"]["region"]["startColumn"],
        )
    )

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "semanticVersion": __version__,
                        "informationUri": TOOL_INFO_URI,
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }


def serialize_sarif(
    findings: list[ASTFinding],
    workspace_root: Optional[Union[Path, str]] = None,
    indent: int = 2,
) -> str:
    """Serialize ASTFindings to a deterministic, formatted SARIF v2.1.0 JSON string."""
    sarif_dict = findings_to_sarif(findings, workspace_root=workspace_root)
    return json.dumps(sarif_dict, indent=indent, sort_keys=True)

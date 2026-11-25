"""Enterprise Baseline & Technical Debt Ratcheting Engine for ConcurrencyGuard.

Provides line-shift-resilient fingerprinting, baseline JSON serialization,
multiset occurrence matching, and downward technical debt ratcheting.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

from concurrency_guard.atomic_io import atomic_write_text

if TYPE_CHECKING:
    from concurrency_guard.scanner.ast_rules import ASTFinding


@dataclass
class BaselineEntry:
    """A single baselined vulnerability finding snapshot."""

    fingerprint: str
    rule_id: str
    file: str
    function: str
    line: int
    message: str
    snippet_hash: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert entry to JSON-serializable dictionary."""
        d: dict[str, Any] = {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "message": self.message,
        }
        if self.snippet_hash:
            d["snippet_hash"] = self.snippet_hash
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineEntry:
        """Create BaselineEntry from dictionary payload."""
        return cls(
            fingerprint=str(data["fingerprint"]),
            rule_id=str(data["rule_id"]),
            file=str(data["file"]),
            function=str(data.get("function", "<module>")),
            line=int(data.get("line", 1)),
            message=str(data.get("message", "")),
            snippet_hash=str(data["snippet_hash"]) if data.get("snippet_hash") else None,
        )


@dataclass
class Baseline:
    """Persistent snapshot of known technical debt in .cguard-baseline.json."""

    version: int = 1
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cguard_version: str = ""
    total_baselined: int = 0
    findings: list[BaselineEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert entire baseline to JSON-serializable dictionary."""
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "cguard_version": self.cguard_version,
            "total_baselined": self.total_baselined,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize baseline to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Baseline:
        """Construct Baseline instance from parsed JSON dictionary."""
        findings = [BaselineEntry.from_dict(item) for item in data.get("findings", [])]
        return cls(
            version=int(data.get("version", 1)),
            generated_at=str(data.get("generated_at", "")),
            cguard_version=str(data.get("cguard_version", "")),
            total_baselined=int(data.get("total_baselined", len(findings))),
            findings=findings,
        )

    @classmethod
    def from_json(cls, json_str: str) -> Baseline:
        """Construct Baseline instance from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def load(cls, path: Union[str, Path]) -> Baseline:
        """Load Baseline from a file path."""
        p = Path(path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Baseline file not found: {path}")
        return cls.from_json(p.read_text(encoding="utf-8"))

    def save(self, path: Union[str, Path]) -> None:
        """Save Baseline deterministically to a file path."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(p, self.to_json() + "\n")


@dataclass
class BaselineFilterResult:
    """Outcome of filtering active findings against a baseline."""

    new_findings: list[ASTFinding]
    baselined_findings: list[ASTFinding]
    resolved_entries: list[BaselineEntry]
    total_active: int
    total_baselined: int
    total_new: int
    total_resolved: int

    @property
    def summary_footer(self) -> str:
        """Format standardized summary string for CLI and CI logs."""
        return (
            f"Baselined: {self.total_baselined} suppressed | "
            f"New: {self.total_new} active | "
            f"Resolved: {self.total_resolved} fixed"
        )


def normalize_relative_path(path_str: str, root_dir: Optional[Union[str, Path]] = None) -> str:
    """Normalize file path to a POSIX-compliant relative path."""
    p = Path(path_str)
    root = Path(root_dir).resolve() if root_dir is not None else Path.cwd().resolve()
    try:
        resolved = p.resolve()
        rel = resolved.relative_to(root)
        return str(rel).replace("\\", "/")
    except (ValueError, RuntimeError):
        pass

    norm = path_str.replace("\\", "/")
    norm = norm.removeprefix("./")
    return norm


def get_finding_source_snippet(
    finding: ASTFinding,
    root_dir: Optional[Union[str, Path]] = None,
    source_cache: Optional[dict[str, list[str]]] = None,
) -> tuple[str, str]:
    """Retrieve normalized source line and its SHA-256 digest for a finding."""
    cache = source_cache if source_cache is not None else {}
    filename = finding.filename

    lines = cache.get(filename)
    if lines is None:
        file_path = Path(filename)
        if not file_path.is_absolute() and root_dir is not None:
            file_path = Path(root_dir) / filename
        if file_path.is_file():
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                cache[filename] = lines
            except OSError:
                lines = []
        else:
            lines = []

    if lines and 1 <= finding.lineno <= len(lines):
        raw_line = lines[finding.lineno - 1]
        normalized = " ".join(raw_line.strip().split())
    else:
        normalized = " ".join(finding.message.strip().split())

    snippet_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return normalized, snippet_hash


def compute_finding_fingerprint(
    finding: ASTFinding,
    root_dir: Optional[Union[str, Path]] = None,
    source_cache: Optional[dict[str, list[str]]] = None,
) -> tuple[str, str, str]:
    """Compute line-shift-resilient canonical SHA-256 fingerprint for an ASTFinding.

    Components:
    1. rule_id (e.g. CG-001)
    2. POSIX relative file path
    3. Function qualified name
    4. Normalized source snippet SHA-256 hash
    """
    rule_id = finding.rule_id.strip().upper()
    norm_file = normalize_relative_path(finding.filename, root_dir=root_dir)
    func_name = finding.function_name.strip() if finding.function_name else "<module>"
    _, snippet_hash = get_finding_source_snippet(finding, root_dir=root_dir, source_cache=source_cache)

    preimage = f"{rule_id}:{norm_file}:{func_name}:{snippet_hash}"
    fingerprint = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    return fingerprint, norm_file, snippet_hash


def create_baseline(
    findings: list[ASTFinding],
    root_dir: Optional[Union[str, Path]] = None,
    version: int = 1,
    cguard_version: str = "",
) -> Baseline:
    """Generate a sorted, deterministic Baseline from a list of AST findings."""
    source_cache: dict[str, list[str]] = {}
    entries: list[BaselineEntry] = []

    for f in findings:
        fp, norm_file, snip_hash = compute_finding_fingerprint(
            f, root_dir=root_dir, source_cache=source_cache
        )
        entry = BaselineEntry(
            fingerprint=fp,
            rule_id=f.rule_id.strip().upper(),
            file=norm_file,
            function=f.function_name.strip() if f.function_name else "<module>",
            line=f.lineno,
            message=f.message.strip(),
            snippet_hash=snip_hash,
        )
        entries.append(entry)

    # Deterministic sorting
    entries.sort(key=lambda e: (e.file, e.line, e.rule_id, e.fingerprint))

    return Baseline(
        version=version,
        generated_at=datetime.now(timezone.utc).isoformat(),
        cguard_version=cguard_version,
        total_baselined=len(entries),
        findings=entries,
    )


def filter_with_baseline(
    active_findings: list[ASTFinding],
    baseline: Baseline,
    root_dir: Optional[Union[str, Path]] = None,
) -> BaselineFilterResult:
    """Filter active findings against baseline using multiset/occurrence matching.

    If a function contains 2 baselined findings and 3 active findings match the fingerprint,
    the first 2 are baselined and the 3rd is flagged as NEW.
    Unmatched baseline entries are returned as resolved_entries.
    """
    source_cache: dict[str, list[str]] = {}
    available_entries: dict[str, list[BaselineEntry]] = defaultdict(list)
    for entry in baseline.findings:
        available_entries[entry.fingerprint].append(entry)

    new_findings: list[ASTFinding] = []
    baselined_findings: list[ASTFinding] = []

    for finding in active_findings:
        fp, _, _ = compute_finding_fingerprint(
            finding, root_dir=root_dir, source_cache=source_cache
        )
        if available_entries.get(fp):
            available_entries[fp].pop(0)
            baselined_findings.append(finding)
        else:
            new_findings.append(finding)

    resolved_entries: list[BaselineEntry] = []
    for remaining in available_entries.values():
        resolved_entries.extend(remaining)

    # Deterministic sort for resolved entries
    resolved_entries.sort(key=lambda e: (e.file, e.line, e.rule_id, e.fingerprint))

    return BaselineFilterResult(
        new_findings=new_findings,
        baselined_findings=baselined_findings,
        resolved_entries=resolved_entries,
        total_active=len(active_findings),
        total_baselined=len(baselined_findings),
        total_new=len(new_findings),
        total_resolved=len(resolved_entries),
    )


def update_baseline_file(
    baseline_path: Union[str, Path],
    remaining_baselined_findings: list[ASTFinding],
    root_dir: Optional[Union[str, Path]] = None,
    cguard_version: str = "",
) -> Baseline:
    """Update baseline file strictly downward by removing resolved findings."""
    updated = create_baseline(
        remaining_baselined_findings,
        root_dir=root_dir,
        cguard_version=cguard_version,
    )
    updated.save(baseline_path)
    return updated


__all__ = [
    "Baseline",
    "BaselineEntry",
    "BaselineFilterResult",
    "compute_finding_fingerprint",
    "create_baseline",
    "filter_with_baseline",
    "get_finding_source_snippet",
    "normalize_relative_path",
    "update_baseline_file",
]

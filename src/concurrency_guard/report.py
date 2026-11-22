"""Executive Concurrency Health Scorer & Metrics Aggregator.

Computes a deterministic Concurrency Health Score (0–100), letter grade (A–F),
CWE compliance breakdown, auto-fixable counts, and hotspot file ranking across
static AST findings and scanned files.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from concurrency_guard.sarif import RULE_REGISTRY
from concurrency_guard.scanner.ast_rules import ASTFinding

AUTO_FIXABLE_RULES: frozenset[str] = frozenset({
    "CG-001",
    "CG-002",
    "CG-004",
    "CG-006",
    "CG-007",
    "CG-008",
    "CG-009",
    "CG-016",
    "CG-017",
    "CG-022",
    "CG-025",
})

SEVERITY_DEDUCTIONS: dict[str, int] = {
    "HIGH": 12,
    "MEDIUM": 5,
    "LOW": 2,
}


def get_finding_severity(finding: ASTFinding) -> str:
    """Return normalized severity ('HIGH', 'MEDIUM', 'LOW') for an AST finding."""
    explicit_sev = getattr(finding, "severity", None)
    if explicit_sev and str(explicit_sev).upper() in SEVERITY_DEDUCTIONS:
        return str(explicit_sev).upper()

    meta = RULE_REGISTRY.get(finding.rule_id, {})
    level = meta.get("defaultConfiguration", {}).get("level", "").lower()
    if level == "error":
        return "HIGH"
    if level == "warning":
        return "MEDIUM"
    if level == "note":
        return "LOW"

    conf = getattr(finding, "confidence", "HIGH") or "HIGH"
    conf_upper = str(conf).upper()
    if conf_upper in SEVERITY_DEDUCTIONS:
        return conf_upper
    return "MEDIUM"


def is_auto_fixable(finding: ASTFinding) -> bool:
    """Check if a deterministic LibCST patcher is available for this finding."""
    return finding.rule_id in AUTO_FIXABLE_RULES


def get_cwe_for_finding(finding: ASTFinding) -> list[str]:
    """Retrieve CWE tags for a finding from rule registry or default to CWE-362."""
    meta = RULE_REGISTRY.get(finding.rule_id, {})
    tags = meta.get("properties", {}).get("tags", [])
    cwes = [t.upper() for t in tags if t.lower().startswith("cwe-")]
    return cwes if cwes else ["CWE-362"]


@dataclass(frozen=True)
class HotspotFile:
    """Aggregated risk score and finding counts for a single hotspot file."""

    path: str
    risk_score: int
    total_findings: int
    high_count: int
    medium_count: int
    low_count: int
    auto_fixable_count: int


@dataclass(frozen=True)
class AuditMetrics:
    """Aggregated Concurrency Health metrics across findings and scanned files."""

    health_score: int
    grade: str
    total_findings: int
    files_scanned: int
    clean_files_count: int
    high_count: int
    medium_count: int
    low_count: int
    auto_fixable_count: int
    cwe_breakdown: dict[str, int]
    rule_breakdown: dict[str, int]
    hotspots: list[HotspotFile]

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to a JSON-serializable dictionary."""
        return {
            "health_score": self.health_score,
            "grade": self.grade,
            "total_findings": self.total_findings,
            "files_scanned": self.files_scanned,
            "clean_files_count": self.clean_files_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "auto_fixable_count": self.auto_fixable_count,
            "cwe_breakdown": dict(self.cwe_breakdown),
            "rule_breakdown": dict(self.rule_breakdown),
            "hotspots": [
                {
                    "path": h.path,
                    "risk_score": h.risk_score,
                    "total_findings": h.total_findings,
                    "high_count": h.high_count,
                    "medium_count": h.medium_count,
                    "low_count": h.low_count,
                    "auto_fixable_count": h.auto_fixable_count,
                }
                for h in self.hotspots
            ],
        }


def compute_audit_metrics(
    findings: list[ASTFinding],
    scanned_files: Optional[list[Union[Path, str]]] = None,
) -> AuditMetrics:
    """Compute deterministic Concurrency Health Score, letter grade, and metrics."""
    high_count = 0
    medium_count = 0
    low_count = 0
    auto_fixable_count = 0

    cwe_counts: dict[str, int] = defaultdict(int)
    rule_counts: dict[str, int] = defaultdict(int)
    file_findings_map: dict[str, list[ASTFinding]] = defaultdict(list)

    for finding in findings:
        sev = get_finding_severity(finding)
        if sev == "HIGH":
            high_count += 1
        elif sev == "MEDIUM":
            medium_count += 1
        else:
            low_count += 1

        if is_auto_fixable(finding):
            auto_fixable_count += 1

        rule_counts[finding.rule_id] += 1
        for cwe in get_cwe_for_finding(finding):
            cwe_counts[cwe] += 1

        file_findings_map[str(finding.filename)].append(finding)

    # Concurrency Health Score: 100 base, deducted by severity weights, clamped to [0, 100]
    total_deductions = (
        high_count * SEVERITY_DEDUCTIONS["HIGH"]
        + medium_count * SEVERITY_DEDUCTIONS["MEDIUM"]
        + low_count * SEVERITY_DEDUCTIONS["LOW"]
    )
    health_score = max(0, min(100, 100 - total_deductions))

    # Letter Grade assignment
    if health_score >= 90:
        grade = "A"
    elif health_score >= 80:
        grade = "B"
    elif health_score >= 70:
        grade = "C"
    elif health_score >= 60:
        grade = "D"
    else:
        grade = "F"

    # Scanned and clean files calculations
    if scanned_files is not None:
        total_files = len(scanned_files)
        files_with_findings = {str(Path(f).resolve()) for f in file_findings_map}
        clean_count = max(
            0,
            sum(1 for sf in scanned_files if str(Path(sf).resolve()) not in files_with_findings),
        )
    else:
        total_files = len(file_findings_map) if file_findings_map else 1
        clean_count = 0 if file_findings_map else 1

    # Hotspot calculation
    hotspots: list[HotspotFile] = []
    for fpath, f_list in file_findings_map.items():
        f_high = sum(1 for f in f_list if get_finding_severity(f) == "HIGH")
        f_med = sum(1 for f in f_list if get_finding_severity(f) == "MEDIUM")
        f_low = sum(1 for f in f_list if get_finding_severity(f) == "LOW")
        f_fixable = sum(1 for f in f_list if is_auto_fixable(f))
        f_risk = (
            f_high * SEVERITY_DEDUCTIONS["HIGH"]
            + f_med * SEVERITY_DEDUCTIONS["MEDIUM"]
            + f_low * SEVERITY_DEDUCTIONS["LOW"]
        )
        hotspots.append(
            HotspotFile(
                path=fpath,
                risk_score=f_risk,
                total_findings=len(f_list),
                high_count=f_high,
                medium_count=f_med,
                low_count=f_low,
                auto_fixable_count=f_fixable,
            )
        )

    hotspots.sort(key=lambda h: (-h.risk_score, -h.total_findings, h.path))

    sorted_cwe = dict(sorted(cwe_counts.items(), key=lambda item: (-item[1], item[0])))
    sorted_rules = dict(sorted(rule_counts.items(), key=lambda item: (-item[1], item[0])))

    return AuditMetrics(
        health_score=health_score,
        grade=grade,
        total_findings=len(findings),
        files_scanned=total_files,
        clean_files_count=clean_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        auto_fixable_count=auto_fixable_count,
        cwe_breakdown=sorted_cwe,
        rule_breakdown=sorted_rules,
        hotspots=hotspots,
    )

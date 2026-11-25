"""Executive Concurrency Health Scorer & Metrics Aggregator.

Computes a deterministic Concurrency Health Score (0–100), letter grade (A–F),
CWE compliance breakdown, auto-fixable counts, and hotspot file ranking across
static AST findings and scanned files.
"""

from __future__ import annotations

import html
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from concurrency_guard import __version__
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
    "CG-033",
})

SEVERITY_DEDUCTIONS: dict[str, int] = {
    "HIGH": 12,
    "MEDIUM": 5,
    "LOW": 2,
}

CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-833": "Deadlock",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)",
    "CWE-662": "Improper Synchronization / Uncontrolled Concurrent Execution",
    "CWE-400": "Uncontrolled Resource Consumption (Event-Loop Starvation & Lock Contention)",
    "CWE-820": "Missing Synchronization",
    "CWE-821": "Incorrect Synchronization",
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
    if finding.cwe is not None:
        return [finding.cwe]
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
    scanned_files: Optional[Sequence[Union[Path, str]]] = None,
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


def _extract_source_snippet(
    filename: str, lineno: int, context_lines: int = 2
) -> Optional[list[tuple[int, str, bool]]]:
    """Read context lines around lineno safely from disk, returning (line_num, line_text, is_target)."""
    try:
        p = Path(filename)
        if not p.is_file():
            return None
        lines = p.read_text(encoding="utf-8-sig").splitlines()
        start = max(1, lineno - context_lines)
        end = min(len(lines), lineno + context_lines)
        result: list[tuple[int, str, bool]] = []
        for curr in range(start, end + 1):
            line_idx = curr - 1
            if 0 <= line_idx < len(lines):
                result.append((curr, lines[line_idx], curr == lineno))
        return result
    except (OSError, UnicodeDecodeError):
        return None


def render_html_report(
    metrics: AuditMetrics,
    findings: list[ASTFinding],
    scanned_files: Optional[Sequence[Union[Path, str]]] = None,
) -> str:
    """Render a 100% self-contained, offline-safe, XSS-escaped interactive HTML5 audit report."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Grade styling configuration
    grade_colors = {
        "A": "#10b981",  # emerald
        "B": "#3b82f6",  # blue
        "C": "#f59e0b",  # amber
        "D": "#f97316",  # orange
        "F": "#ef4444",  # red
    }
    grade_color = grade_colors.get(metrics.grade, "#ef4444")

    # Hotspot table rows
    hotspot_rows: list[str] = []
    for rank, h in enumerate(metrics.hotspots[:10], start=1):
        clean_path = html.escape(h.path)
        hotspot_rows.append(
            f"<tr>"
            f"<td class='text-center text-muted'>{rank}</td>"
            f"<td class='font-mono' title='{clean_path}'>{clean_path}</td>"
            f"<td class='text-center font-bold text-red'>{h.risk_score}</td>"
            f"<td class='text-center'>{h.total_findings}</td>"
            f"<td class='text-center text-red'>{h.high_count}</td>"
            f"<td class='text-center text-amber'>{h.medium_count}</td>"
            f"<td class='text-center text-blue'>{h.low_count}</td>"
            f"<td class='text-center text-purple'>{h.auto_fixable_count}</td>"
            f"</tr>"
        )
    if not hotspot_rows:
        hotspot_rows.append("<tr><td colspan='8' class='text-center text-muted py-4'>No hotspots detected. Clean codebase!</td></tr>")

    # CWE breakdown rows
    cwe_rows: list[str] = []
    total_cwe_occurrences = sum(metrics.cwe_breakdown.values()) or 1
    for cwe_id, count in metrics.cwe_breakdown.items():
        desc = html.escape(CWE_DESCRIPTIONS.get(cwe_id, "Concurrency & Synchronization Hazard"))
        clean_cwe = html.escape(cwe_id)
        pct = (count / total_cwe_occurrences) * 100
        cwe_rows.append(
            f"<tr>"
            f"<td class='font-bold'>{clean_cwe}</td>"
            f"<td class='text-muted'>{desc}</td>"
            f"<td class='text-right font-bold'>{count}</td>"
            f"<td style='width: 140px;'>"
            f"  <div class='progress-track'><div class='progress-fill' style='width: {pct:.1f}%;'></div></div>"
            f"</td>"
            f"</tr>"
        )
    if not cwe_rows:
        cwe_rows.append("<tr><td colspan='4' class='text-center text-muted py-4'>100% CWE compliant. Zero concurrency vulnerabilities!</td></tr>")

    # Finding cards
    finding_cards: list[str] = []
    for idx, f in enumerate(findings, start=1):
        sev = get_finding_severity(f)
        clean_rule = html.escape(f.rule_id)
        clean_file = html.escape(str(f.filename))
        clean_line = str(f.lineno)
        clean_func = html.escape(f.function_name)
        clean_msg = html.escape(f.message)
        clean_hint = html.escape(f.suggested_fix_hint)
        fixable = is_auto_fixable(f)

        sev_class = "sev-high" if sev == "HIGH" else ("sev-med" if sev == "MEDIUM" else "sev-low")

        # Source context snippet
        snippet = _extract_source_snippet(f.filename, f.lineno)
        snippet_html = ""
        if snippet:
            snippet_lines = []
            for lnum, ltext, is_target in snippet:
                cls = "code-line target-line" if is_target else "code-line"
                ind = "▶" if is_target else " "
                escaped_code = html.escape(ltext)
                snippet_lines.append(
                    f"<div class='{cls}'><span class='line-no'>{lnum}</span><span class='line-ind'>{ind}</span>{escaped_code}</div>"
                )
            snippet_html = f"<div class='snippet-wrapper'><div class='snippet-header'>{clean_file}:{clean_line}</div><pre><code>{''.join(snippet_lines)}</code></pre></div>"

        fix_badge = (
            "<span class='badge badge-fixable' title='Deterministic LibCST auto-fix available'>⚡ AUTO-FIXABLE</span>"
            if fixable
            else ""
        )

        fix_remediation = (
            f"<div class='fix-box'>"
            f"  <div class='fix-title'>Remediation Guidance</div>"
            f"  <div class='fix-desc'>{clean_hint}</div>"
            + (
                f"  <div class='fix-command'><code>cguard fix {clean_file} --write</code></div>"
                if fixable
                else ""
            )
            + "</div>"
        )

        finding_cards.append(
            f"<details class='finding-card' data-severity='{sev}' data-rule='{clean_rule}' data-fixable='{str(fixable).lower()}' open>"
            f"  <summary class='card-summary'>"
            f"    <div class='summary-left'>"
            f"      <span class='badge {sev_class}'>{sev}</span>"
            f"      <span class='badge badge-rule'>{clean_rule}</span>"
            f"      {fix_badge}"
            f"      <span class='finding-loc'>{clean_file}:{clean_line}</span>"
            f"      <span class='finding-func'>in <code>{clean_func}()</code></span>"
            f"    </div>"
            f"    <div class='summary-arrow'>▼</div>"
            f"  </summary>"
            f"  <div class='card-body'>"
            f"    <div class='card-message'>{clean_msg}</div>"
            f"    {snippet_html}"
            f"    {fix_remediation}"
            f"  </div>"
            f"</details>"
        )

    cards_html = (
        "".join(finding_cards)
        if finding_cards
        else "<div class='clean-banner'><div class='clean-title'>🛡️ Clean Repository</div><div class='clean-sub'>Zero concurrency vulnerabilities, race conditions, or lock leaks detected.</div></div>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ConcurrencyGuard Executive Audit Report</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --surface: #1e293b;
      --surface-alt: #162032;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent: #38bdf8;
      --sev-high: #ef4444;
      --sev-med: #f59e0b;
      --sev-low: #3b82f6;
      --purple: #a855f7;
      --green: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 2rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
    }}
    .brand {{ display: flex; align-items: center; gap: 0.75rem; }}
    .logo-badge {{
      background: linear-gradient(135deg, #FF4D1C, #f97316);
      color: white;
      font-weight: 800;
      font-size: 1.1rem;
      padding: 0.4rem 0.8rem;
      border-radius: 8px;
    }}
    .title-block h1 {{ font-size: 1.5rem; font-weight: 700; }}
    .title-block .timestamp {{ font-size: 0.85rem; color: var(--text-muted); }}
    .score-badge {{
      display: flex;
      align-items: center;
      gap: 1rem;
      background: var(--surface);
      border: 2px solid {grade_color};
      padding: 0.75rem 1.5rem;
      border-radius: 12px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }}
    .grade-circle {{
      font-size: 2.2rem;
      font-weight: 900;
      color: {grade_color};
      line-height: 1;
    }}
    .score-info .score-val {{ font-size: 1.3rem; font-weight: 700; }}
    .score-info .score-label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
    
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .kpi-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
    }}
    .kpi-label {{ font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.4rem; }}
    .kpi-val {{ font-size: 1.8rem; font-weight: 700; }}
    .kpi-sub {{ font-size: 0.8rem; color: var(--text-dim); margin-top: 0.2rem; }}

    .two-col {{
      display: grid;
      grid-template-columns: 3fr 2fr;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }}
    @media (max-width: 900px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
    .panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
      overflow-x: auto;
    }}
    .panel-title {{
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    th {{
      text-align: left;
      padding: 0.6rem 0.75rem;
      border-bottom: 1px solid var(--border);
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    td {{
      padding: 0.6rem 0.75rem;
      border-bottom: 1px solid rgba(51, 65, 85, 0.4);
    }}
    tr:last-child td {{ border-bottom: none; }}
    .text-center {{ text-align: center; }}
    .text-right {{ text-align: right; }}
    .text-muted {{ color: var(--text-muted); }}
    .text-red {{ color: var(--sev-high); }}
    .text-amber {{ color: var(--sev-med); }}
    .text-blue {{ color: var(--sev-low); }}
    .text-purple {{ color: var(--purple); }}
    .font-bold {{ font-weight: 700; }}
    .font-mono {{ font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: 0.8rem; }}
    
    .progress-track {{
      background: var(--bg);
      border-radius: 999px;
      height: 8px;
      width: 100%;
      overflow: hidden;
    }}
    .progress-fill {{
      background: linear-gradient(90deg, #38bdf8, #818cf8);
      height: 100%;
      border-radius: 999px;
    }}

    .controls-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.75rem 1.25rem;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }}
    .filter-group {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
    .filter-btn {{
      background: var(--surface-alt);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .filter-btn:hover {{ color: var(--text); border-color: var(--accent); }}
    .filter-btn.active {{ background: var(--accent); color: #000; border-color: var(--accent); }}
    .search-box {{
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      font-size: 0.85rem;
      min-width: 260px;
    }}
    .search-box:focus {{ outline: none; border-color: var(--accent); }}
    .action-links {{ display: flex; gap: 0.5rem; font-size: 0.8rem; color: var(--text-muted); cursor: pointer; }}
    .action-link:hover {{ color: var(--text); text-decoration: underline; }}

    .finding-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 1rem;
      overflow: hidden;
      transition: border-color 0.15s ease;
    }}
    .finding-card:hover {{ border-color: var(--text-dim); }}
    .card-summary {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem 1.25rem;
      cursor: pointer;
      user-select: none;
      background: var(--surface);
    }}
    .card-summary::-webkit-details-marker {{ display: none; }}
    .summary-left {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }}
    .summary-arrow {{ font-size: 0.75rem; color: var(--text-muted); transition: transform 0.2s ease; }}
    .finding-card[open] .summary-arrow {{ transform: rotate(180deg); }}
    .badge {{
      font-size: 0.75rem;
      font-weight: 700;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      letter-spacing: 0.05em;
    }}
    .sev-high {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .sev-med {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .sev-low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
    .badge-rule {{ background: var(--surface-alt); color: var(--text); border: 1px solid var(--border); font-family: ui-monospace, monospace; }}
    .badge-fixable {{ background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); }}
    .finding-loc {{ font-family: ui-monospace, monospace; font-size: 0.85rem; font-weight: 600; color: var(--text); }}
    .finding-func {{ font-size: 0.85rem; color: var(--text-muted); }}

    .card-body {{
      padding: 1.25rem;
      background: var(--surface-alt);
      border-top: 1px solid var(--border);
    }}
    .card-message {{ font-size: 0.95rem; margin-bottom: 1rem; color: var(--text); }}
    .snippet-wrapper {{
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
      margin-bottom: 1rem;
      font-family: ui-monospace, monospace;
      font-size: 0.85rem;
    }}
    .snippet-header {{
      background: rgba(51, 65, 85, 0.3);
      padding: 0.3rem 0.75rem;
      font-size: 0.75rem;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
    }}
    pre {{ margin: 0; padding: 0.5rem 0; overflow-x: auto; }}
    .code-line {{ display: flex; padding: 0.15rem 0.75rem; }}
    .target-line {{ background: rgba(239, 68, 68, 0.15); border-left: 3px solid var(--sev-high); }}
    .line-no {{ width: 3rem; color: var(--text-dim); text-align: right; margin-right: 0.75rem; user-select: none; }}
    .line-ind {{ width: 1.2rem; color: var(--sev-high); font-weight: 700; user-select: none; }}
    
    .fix-box {{
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 6px;
      padding: 0.85rem;
    }}
    .fix-title {{ font-size: 0.8rem; font-weight: 700; color: var(--green); text-transform: uppercase; margin-bottom: 0.3rem; }}
    .fix-desc {{ font-size: 0.9rem; color: var(--text); margin-bottom: 0.4rem; }}
    .fix-command {{ font-family: ui-monospace, monospace; font-size: 0.8rem; color: var(--accent); }}

    .clean-banner {{
      background: var(--surface);
      border: 2px solid var(--green);
      border-radius: 12px;
      padding: 3rem;
      text-align: center;
    }}
    .clean-title {{ font-size: 1.5rem; font-weight: 800; color: var(--green); margin-bottom: 0.5rem; }}
    .clean-sub {{ color: var(--text-muted); font-size: 1rem; }}
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div class="brand">
        <div class="logo-badge">cguard</div>
        <div class="title-block">
          <h1>Executive Concurrency Health Report</h1>
          <div class="timestamp">Generated on {timestamp} • ConcurrencyGuard v{__version__}</div>
        </div>
      </div>
      <div class="score-badge">
        <div class="grade-circle">{metrics.grade}</div>
        <div class="score-info">
          <div class="score-val">{metrics.health_score} / 100</div>
          <div class="score-label">Health Score</div>
        </div>
      </div>
    </header>

    <section class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Total Findings</div>
        <div class="kpi-val">{metrics.total_findings}</div>
        <div class="kpi-sub">{metrics.clean_files_count} clean file(s)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">High Severity</div>
        <div class="kpi-val text-red">{metrics.high_count}</div>
        <div class="kpi-sub">Immediate race hazards</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Auto-Fixable</div>
        <div class="kpi-val text-purple">{metrics.auto_fixable_count}</div>
        <div class="kpi-sub">LibCST patch ready</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Files Scanned</div>
        <div class="kpi-val text-blue">{metrics.files_scanned}</div>
        <div class="kpi-sub">{len(metrics.hotspots)} hotspot file(s)</div>
      </div>
    </section>

    <section class="two-col">
      <div class="panel">
        <div class="panel-title">
          <span>Top Hotspot Files</span>
          <span class="text-muted" style="font-size: 0.8rem; font-weight: normal;">Ranked by Risk Score</span>
        </div>
        <table>
          <thead>
            <tr>
              <th class="text-center">#</th>
              <th>File</th>
              <th class="text-center">Risk</th>
              <th class="text-center">Total</th>
              <th class="text-center">High</th>
              <th class="text-center">Med</th>
              <th class="text-center">Low</th>
              <th class="text-center">Auto-Fix</th>
            </tr>
          </thead>
          <tbody>
            {''.join(hotspot_rows)}
          </tbody>
        </table>
      </div>

      <div class="panel">
        <div class="panel-title">
          <span>CWE Compliance Breakdown</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>CWE ID</th>
              <th>Description</th>
              <th class="text-right">Count</th>
              <th>Distribution</th>
            </tr>
          </thead>
          <tbody>
            {''.join(cwe_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <section>
      <div class="controls-bar">
        <div class="filter-group">
          <button class="filter-btn active" data-filter="ALL">All ({metrics.total_findings})</button>
          <button class="filter-btn" data-filter="HIGH">High ({metrics.high_count})</button>
          <button class="filter-btn" data-filter="MEDIUM">Medium ({metrics.medium_count})</button>
          <button class="filter-btn" data-filter="LOW">Low ({metrics.low_count})</button>
          <button class="filter-btn" data-filter="FIXABLE">Auto-Fixable ({metrics.auto_fixable_count})</button>
        </div>
        <input type="text" id="search-input" class="search-box" placeholder="Filter by rule, file, or keyword...">
        <div class="action-links">
          <span class="action-link" id="expand-all">Expand All</span>
          <span>•</span>
          <span class="action-link" id="collapse-all">Collapse All</span>
          <span>•</span>
          <span class="text-muted">Showing <strong id="visible-count">{metrics.total_findings}</strong> findings</span>
        </div>
      </div>

      <div id="findings-container">
        {cards_html}
      </div>
    </section>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', () => {{
      const searchInput = document.getElementById('search-input');
      const filterButtons = document.querySelectorAll('.filter-btn');
      const cards = document.querySelectorAll('.finding-card');
      const counter = document.getElementById('visible-count');

      let currentSeverity = 'ALL';
      let searchQuery = '';

      function updateVisibility() {{
        let visible = 0;
        cards.forEach(card => {{
          const sev = card.getAttribute('data-severity');
          const rule = (card.getAttribute('data-rule') || '').toLowerCase();
          const fixable = card.getAttribute('data-fixable') === 'true';
          const text = card.textContent.toLowerCase();

          let matchesSeverity = false;
          if (currentSeverity === 'ALL') matchesSeverity = true;
          else if (currentSeverity === 'FIXABLE') matchesSeverity = fixable;
          else matchesSeverity = (sev === currentSeverity);

          const matchesSearch = !searchQuery || text.includes(searchQuery) || rule.includes(searchQuery);

          if (matchesSeverity && matchesSearch) {{
            card.style.display = '';
            visible++;
          }} else {{
            card.style.display = 'none';
          }}
        }});
        if (counter) counter.textContent = visible;
      }}

      filterButtons.forEach(btn => {{
        btn.addEventListener('click', () => {{
          filterButtons.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          currentSeverity = btn.getAttribute('data-filter') || 'ALL';
          updateVisibility();
        }});
      }});

      if (searchInput) {{
        searchInput.addEventListener('input', (e) => {{
          searchQuery = e.target.value.trim().toLowerCase();
          updateVisibility();
        }});
      }}

      const expandAll = document.getElementById('expand-all');
      if (expandAll) {{
        expandAll.addEventListener('click', () => {{
          cards.forEach(card => card.open = true);
        }});
      }}

      const collapseAll = document.getElementById('collapse-all');
      if (collapseAll) {{
        collapseAll.addEventListener('click', () => {{
          cards.forEach(card => card.open = false);
        }});
      }}
    }});
  </script>
</body>
</html>
"""


def render_markdown_report(
    metrics: AuditMetrics,
    findings: list[ASTFinding],
) -> str:
    """Render an executive Markdown audit report suitable for GitHub PR comments, Notion, or Confluence."""
    lines: list[str] = [
        "# 🛡️ ConcurrencyGuard Executive Concurrency Audit Report\n",
        f"**Concurrency Health Score:** **{metrics.health_score} / 100** (`Grade {metrics.grade}`)  ",
        f"**Findings:** {metrics.total_findings} total ({metrics.high_count} high, {metrics.medium_count} medium, {metrics.low_count} low)  ",
        f"**Auto-Fixable with LibCST:** {metrics.auto_fixable_count} finding(s)  ",
        f"**Files Scanned:** {metrics.files_scanned} ({metrics.clean_files_count} clean)\n",
        "## 📊 Executive Summary\n",
        "| Health Score | Letter Grade | Total Findings | High Severity | Medium | Low | Auto-Fixable | Files Scanned | Clean Files |",
        "| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| **{metrics.health_score} / 100** | **`{metrics.grade}`** | {metrics.total_findings} | {metrics.high_count} | {metrics.medium_count} | {metrics.low_count} | {metrics.auto_fixable_count} | {metrics.files_scanned} | {metrics.clean_files_count} |\n",
    ]

    # Top Hotspots
    lines.extend([
        "## 🎯 Top Hotspot Files\n",
        "| Rank | File | Risk Score | Total Findings | High | Medium | Low | Auto-Fixable |",
        "| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])
    if metrics.hotspots:
        for idx, h in enumerate(metrics.hotspots[:10], start=1):
            lines.append(
                f"| {idx} | `{h.path}` | **{h.risk_score}** | {h.total_findings} | {h.high_count} | {h.medium_count} | {h.low_count} | {h.auto_fixable_count} |"
            )
    else:
        lines.append("| — | *No hotspots detected. Clean repository!* | 0 | 0 | 0 | 0 | 0 | 0 |")
    lines.append("")

    # CWE Compliance Breakdown
    lines.extend([
        "## 🏷️ CWE Compliance Breakdown\n",
        "| CWE ID | Category Description | Finding Count |",
        "| :--- | :--- | :---: |",
    ])
    if metrics.cwe_breakdown:
        for cwe_id, count in metrics.cwe_breakdown.items():
            desc = CWE_DESCRIPTIONS.get(cwe_id, "Concurrency Hazard")
            lines.append(f"| **{cwe_id}** | {desc} | {count} |")
    else:
        lines.append("| **CWE-362** | 100% Compliant. Zero concurrency race conditions! | 0 |")
    lines.append("")

    # Detailed Findings
    lines.extend([
        "## 🔍 Detailed Concurrency Findings\n",
        "| Rule ID | Severity | Location | Function | Auto-Fixable | Message & Remediation |",
        "| :---: | :---: | :--- | :--- | :---: | :--- |",
    ])
    if findings:
        for f in findings:
            sev = get_finding_severity(f)
            fixable_mark = "⚡ Yes" if is_auto_fixable(f) else "Manual"
            msg = f.message.replace("\n", " ")
            hint = f.suggested_fix_hint.replace("\n", " ")
            loc = f"`{f.filename}:{f.lineno}`"
            func = f"`{f.function_name}()`"
            lines.append(
                f"| `{f.rule_id}` | **{sev}** | {loc} | {func} | {fixable_mark} | {msg}<br/>*💡 {hint}* |"
            )
    else:
        lines.append("| — | — | — | — | — | *No concurrency issues found. Repository is secure!* |")

    lines.append("")
    return "\n".join(lines)

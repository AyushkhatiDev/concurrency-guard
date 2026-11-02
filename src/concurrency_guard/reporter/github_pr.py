"""Generate GitHub Pull Request Markdown reports for concurrency analysis."""

from __future__ import annotations

import difflib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Optional

from concurrency_guard.scanner.ast_rules import ASTFinding


def generate_github_pr_markdown(
    file_path: Path,
    findings: list[ASTFinding],
    barrier_result: Optional[Mapping[str, Any]] = None,
    patched_code: Optional[str] = None,
    original_code: Optional[str] = None,
) -> str:
    """Generate a clean GitHub PR Markdown comment summarizing scan findings and proofs."""
    lines: list[str] = []

    if original_code is None and file_path.is_file():
        original_code = file_path.read_text(encoding="utf-8")

    has_violation = bool(findings or (barrier_result and barrier_result.get("invariant_violated")))

    # Title & summary badge
    if not has_violation:
        lines.append("## ✅ ConcurrencyGuard Verification Passed\n")
        lines.append(
            f"No concurrency race conditions or idempotency vulnerabilities were detected in `{file_path.name}`.\n"
        )
    else:
        lines.append("## 🚨 ConcurrencyGuard Verification Report\n")
        lines.append(
            f"Detected **{len(findings)}** concurrency / idempotency issue(s) in `{file_path.name}`.\n"
        )

    # Findings Table
    if findings:
        lines.append("### 🔍 Detected Vulnerabilities\n")
        lines.append("| Rule ID | Location | Function | Issue | Suggested Fix |")
        lines.append("|:---|:---|:---|:---|:---|")
        for f in findings:
            clean_message = f.message.replace("|", "\\|")
            clean_hint = f.suggested_fix_hint.replace("|", "\\|")
            lines.append(
                f"| `{f.rule_id}` | `line {f.lineno}` | `{f.function_name}` | {clean_message} | {clean_hint} |"
            )
        lines.append("")

    # Runtime Exploit Proof
    if barrier_result is not None:
        if barrier_result.get("invariant_violated"):
            lines.append("### 💥 Runtime Concurrency Exploit Proof\n")
            lines.append("> [!CAUTION]")
            lines.append("> **Invariant Violation Confirmed via `asyncio.Barrier` Synchronization!**")
            lines.append(f"> - **Concurrent Workers**: `{barrier_result.get('workers')}`")
            lines.append(f"> - **Initial State**: `${barrier_result.get('initial_balance')}`")
            lines.append(
                f"> - **Successful Concurrent Requests**: `{barrier_result.get('success_count')}`"
            )
            lines.append(
                f"> - **Final Resulting State**: `${barrier_result.get('final_balance')}`"
            )
            lines.append(
                ">\n> *Multiple concurrent requests bypassed balance validation due to an unlocked Read-Modify-Write race condition.*\n"
            )
        else:
            lines.append("### 🛡️ Runtime Concurrency Verification\n")
            lines.append("> [!NOTE]")
            lines.append("> **Invariant Preserved Under Barrier Stress!**")
            lines.append(f"> - **Concurrent Workers**: `{barrier_result.get('workers')}`")
            lines.append(
                f"> - **Successful Requests**: `{barrier_result.get('success_count')}`"
            )
            lines.append(f"> - **Final State**: `${barrier_result.get('final_balance')}`\n")

    # Collapsible LibCST Patch Diff
    if patched_code is not None and original_code is not None and patched_code != original_code:
        diff_lines = list(
            difflib.unified_diff(
                original_code.splitlines(keepends=True),
                patched_code.splitlines(keepends=True),
                fromfile=str(file_path),
                tofile=f"{file_path} (patched)",
            )
        )
        if diff_lines:
            diff_str = "".join(diff_lines)
            lines.append("<details>")
            lines.append("<summary>🔧 Deterministic LibCST Auto-Patch Diff</summary>\n")
            lines.append("```diff")
            lines.append(diff_str.rstrip())
            lines.append("```")
            lines.append("</details>\n")

    lines.append("---")
    lines.append(
        "*Deterministic verification by [ConcurrencyGuard](https://github.com/AyushkhatiDev/concurrency-guard)*"
    )

    return "\n".join(lines)

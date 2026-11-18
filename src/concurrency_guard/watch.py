"""Real-time incremental file watcher for ConcurrencyGuard.

Monitors Python files using os.stat mtime + SHA-256 digests, re-scanning
only modified files for near-instant feedback in the terminal.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from concurrency_guard.config import CGuardConfig, load_cguard_config
from concurrency_guard.scanner.ast_rules import (
    ASTFinding,
    discover_python_files,
    scan_source_code,
)


@dataclass(frozen=True)
class FileSnapshot:
    """Snapshot of a file's modification state."""

    path: Path
    mtime_ns: int
    sha256: str


@dataclass
class WatchResult:
    """Result of a single watch cycle."""

    cycle: int
    scanned_files: int
    changed_files: int
    findings: list[ASTFinding]
    elapsed_ms: float
    errors: list[str] = field(default_factory=list)


def _compute_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _snapshot_file(path: Path) -> Optional[FileSnapshot]:
    """Create a snapshot of a file's current state."""
    try:
        stat = os.stat(path)
    except OSError:
        return None
    sha = _compute_sha256(path)
    return FileSnapshot(path=path, mtime_ns=stat.st_mtime_ns, sha256=sha)


def _detect_changes(
    py_files: list[Path],
    previous: dict[Path, FileSnapshot],
) -> tuple[list[Path], dict[Path, FileSnapshot]]:
    """Detect which files have changed since the previous snapshot.

    Returns (changed_files, updated_snapshot_dict).
    """
    changed: list[Path] = []
    current: dict[Path, FileSnapshot] = {}

    for path in py_files:
        snap = _snapshot_file(path)
        if snap is None:
            continue
        current[path] = snap

        prev = previous.get(path)
        if prev is None:
            # New file
            changed.append(path)
        elif prev.mtime_ns != snap.mtime_ns or prev.sha256 != snap.sha256:
            # Modified file
            changed.append(path)

    return changed, current


def _scan_files(files: list[Path], config: Optional[CGuardConfig] = None) -> tuple[list[ASTFinding], list[str]]:
    """Scan a list of files and return (findings, errors)."""
    findings: list[ASTFinding] = []
    errors: list[str] = []

    for path in files:
        try:
            source = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as err:
            errors.append(f"Could not read {path}: {err}")
            continue

        try:
            file_findings = scan_source_code(
                source,
                filename=str(path),
                config=config,
            )
            findings.extend(file_findings)
        except SyntaxError:
            pass
        except Exception as err:  # noqa: BLE001
            errors.append(f"Scan error in {path}: {err}")

    return findings, errors


def _format_terminal_output(
    result: WatchResult,
    *,
    colorize: bool = True,
) -> str:
    """Format a watch cycle result for terminal display."""
    lines: list[str] = []

    timestamp = time.strftime("%H:%M:%S")
    header = f"[{timestamp}] Cycle #{result.cycle}: scanned {result.scanned_files} file(s), {result.changed_files} changed ({result.elapsed_ms:.0f}ms)"

    if colorize:
        lines.append(f"\033[1;36m{header}\033[0m")
    else:
        lines.append(header)

    if result.errors:
        for err in result.errors:
            if colorize:
                lines.append(f"  \033[33m⚠ {err}\033[0m")
            else:
                lines.append(f"  ⚠ {err}")

    if result.findings:
        for f in result.findings:
            severity = "ERROR" if (f.confidence or "HIGH").upper() == "HIGH" else "WARN "
            line = f"  [{f.rule_id}] {severity} {f.filename}:{f.lineno} {f.function_name}: {f.message}"
            if colorize:
                color = "\033[1;31m" if severity.startswith("E") else "\033[1;33m"
                lines.append(f"  {color}[{f.rule_id}]\033[0m {f.filename}:{f.lineno} {f.function_name}: {f.message}")
            else:
                lines.append(line)

        summary = f"  Found {len(result.findings)} issue(s)"
        if colorize:
            lines.append(f"\033[1;31m{summary}\033[0m")
        else:
            lines.append(summary)
    else:
        summary = "  ✔ No concurrency issues found"
        if colorize:
            lines.append(f"\033[1;32m{summary}\033[0m")
        else:
            lines.append(summary)

    return "\n".join(lines)


def watch_project(
    path: Path,
    *,
    interval: float = 0.5,
    max_cycles: Optional[int] = None,
    once: bool = False,
    auto_fix: bool = False,
    config: Optional[CGuardConfig] = None,
    output_stream: Any = None,
    colorize: Optional[bool] = None,
) -> list[WatchResult]:
    """Run the file watcher loop.

    Args:
        path: Directory or file to watch.
        interval: Polling interval in seconds.
        max_cycles: Maximum number of cycles (None = infinite).
        once: If True, run exactly one cycle and exit.
        auto_fix: If True, apply LibCST fixes on changed files.
        config: Optional CGuardConfig for rule/exclusion settings.
        output_stream: Stream for output (defaults to sys.stderr).
        colorize: Whether to use ANSI colors (auto-detect if None).

    Returns:
        List of WatchResult for each completed cycle.
    """
    if once:
        max_cycles = 1

    out = output_stream or sys.stderr
    if colorize is None:
        colorize = hasattr(out, "isatty") and out.isatty()

    if config is None:
        try:
            config = load_cguard_config(start_path=path)
        except (FileNotFoundError, ValueError):
            config = None

    snapshots: dict[Path, FileSnapshot] = {}
    results: list[WatchResult] = []
    cycle = 0

    while True:
        cycle += 1
        start = time.perf_counter()

        py_files = discover_python_files(path, config=config)

        if cycle == 1:
            # First cycle: scan all files
            changed_files = py_files
            # Build initial snapshots
            for f in py_files:
                snap = _snapshot_file(f)
                if snap is not None:
                    snapshots[f] = snap
        else:
            changed_files, snapshots = _detect_changes(py_files, snapshots)

        if not changed_files and cycle > 1:
            # No changes detected, skip scan
            elapsed = (time.perf_counter() - start) * 1000
            if max_cycles is not None and cycle >= max_cycles:
                break
            time.sleep(interval)
            continue

        findings, errors = _scan_files(changed_files, config=config)

        if auto_fix and findings:
            try:
                from concurrency_guard.patcher.cst_fixer import fix_file

                for changed_path in changed_files:
                    fix_file(changed_path, dry_run=False, write_to_disk=True)
            except Exception as err:  # noqa: BLE001
                errors.append(f"Auto-fix error: {err}")

        elapsed = (time.perf_counter() - start) * 1000

        result = WatchResult(
            cycle=cycle,
            scanned_files=len(py_files),
            changed_files=len(changed_files),
            findings=findings,
            elapsed_ms=elapsed,
            errors=errors,
        )
        results.append(result)

        output_text = _format_terminal_output(result, colorize=colorize)
        out.write(output_text + "\n")
        if hasattr(out, "flush"):
            out.flush()

        if max_cycles is not None and cycle >= max_cycles:
            break

        time.sleep(interval)

    return results


__all__ = [
    "FileSnapshot",
    "WatchResult",
    "watch_project",
]

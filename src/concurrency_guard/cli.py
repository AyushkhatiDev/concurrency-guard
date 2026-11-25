"""Command line interface for Concurrency Guard."""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import json
import os
import sys
import time
import urllib.error
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from concurrency_guard import __version__
from concurrency_guard.atomic_io import atomic_write_text
from concurrency_guard.baseline import (
    Baseline,
    BaselineFilterResult,
    create_baseline,
    filter_with_baseline,
    update_baseline_file,
)
from concurrency_guard.cache.file_cache import DEFAULT_CACHE_DIR, FileCache
from concurrency_guard.cache.manager import (
    CacheManager,
    compute_rules_hash,
)
from concurrency_guard.config import load_cguard_config
from concurrency_guard.gh_review import (
    ReviewComment,
    detect_github_environment,
    fetch_existing_pr_comments,
    fetch_pr_diff,
    format_suggestion_comment,
    get_pr_diff,
    is_duplicate_comment,
    map_finding_to_pr_diff,
    post_pr_review_comment,
)
from concurrency_guard.lsp import run_lsp_server
from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.patcher.diff_utils import DiffGenerator, colorize_diff
from concurrency_guard.report import (
    compute_audit_metrics,
    render_html_report,
    render_markdown_report,
)
from concurrency_guard.reporter.github_pr import generate_github_pr_markdown
from concurrency_guard.runner.barrier_engine import (
    BarrierResult,
    DynamicBarrierResult,
    run_barrier_test,
    run_dynamic_barrier_verification,
)
from concurrency_guard.runner.runtime_verifier import verify_function
from concurrency_guard.sarif import serialize_sarif
from concurrency_guard.scanner.ast_rules import (
    discover_python_files,
    load_yaml_rules,
    scan_file,
    scan_project,
    scan_source_code,
)
from concurrency_guard.scanner.git_filter import get_changed_python_files
from concurrency_guard.scanner.suppression import SuppressionFilter
from concurrency_guard.simulator import InterleavingTrace, simulate_finding
from concurrency_guard.watch import watch_project

app = typer.Typer(no_args_is_help=True, help="Deterministic Concurrency & Idempotency Verifier")
console = Console()


@app.callback()
def main() -> None:
    """Deterministic AST + Runtime Concurrency & Idempotency Verifier."""


def _parse_cli_rules(raw_rules: Optional[list[str]]) -> list[str]:
    """Parse comma-separated or multi-flag rule strings into normalized rule IDs."""
    if not raw_rules:
        return []
    result: list[str] = []
    for item in raw_rules:
        for r in item.split(","):
            cleaned = r.strip().upper()
            if cleaned:
                result.append(cleaned)
    return result


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        exists=True,
        help="File or directory to scan for concurrency bugs",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format: 'table', 'json', or 'sarif'",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write scan report directly to an output file (e.g. results.sarif or report.json).",
    ),
    rules: Optional[Path] = typer.Option(None, "--rules", help="YAML file containing custom concurrency rules"),
    cache_path: Optional[Path] = typer.Option(
        None,
        "--cache-path",
        help="Path to SQLite cache database (defaults to .concurrency_guard_cache.db)",
    ),
    cache: bool = typer.Option(True, "--cache/--no-cache", help="Enable or bypass incremental cache reads and writes."),
    clear_cache: bool = typer.Option(
        False,
        "--clear-cache",
        help="Wipe the incremental scan cache before scanning.",
    ),
    cache_dir: Optional[Path] = typer.Option(
        None,
        "--cache-dir",
        help="Directory storing incremental SHA-256 cache entries (defaults to .cguard_cache).",
    ),
    changed_only: bool = typer.Option(
        False,
        "--changed-only",
        help="Only scan files modified in git (staged, unstaged, or untracked).",
    ),
    base_ref: Optional[str] = typer.Option(
        None,
        "--base-ref",
        help="Git base reference (e.g. origin/main, HEAD~1) to compare against for changed files.",
    ),
    jobs: Optional[int] = typer.Option(
        None,
        "--jobs",
        "-j",
        help="Number of worker processes for parallel scanning (0 or omitted = auto-detect CPU count, 1 = single-process deterministic).",
    ),
    workers: Optional[int] = typer.Option(
        None,
        "--workers",
        "-w",
        help="Legacy alias for --jobs.",
    ),
    confidence: Optional[str] = typer.Option(
        None,
        "--confidence",
        help="Filter findings by minimum confidence level: 'high', 'medium', or 'low'.",
    ),
    ignore_pragma: bool = typer.Option(
        False,
        "--ignore-pragma",
        help="Bypass inline '# cguard: ignore' pragma comments and report all findings.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to dedicated configuration file (.cguard.toml, cguard.toml, or pyproject.toml).",
    ),
    select_rules: Optional[list[str]] = typer.Option(
        None,
        "--select-rule",
        "-s",
        help="Whitelist specific rule IDs (e.g. -s CG-001 -s CG-002, or comma-separated).",
    ),
    ignore_rules: Optional[list[str]] = typer.Option(
        None,
        "--ignore-rule",
        "-i",
        help="Ignore specific rule IDs (e.g. -i CG-003, or comma-separated).",
    ),
    baseline: Optional[Path] = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Path to .cguard-baseline.json to suppress existing findings.",
    ),
    update_baseline: bool = typer.Option(
        False,
        "--update-baseline",
        help="Update baseline file by removing resolved findings (downward ratcheting).",
    ),
    fail_on_stale_baseline: bool = typer.Option(
        False,
        "--fail-on-stale-baseline",
        help="Exit code 1 if baseline contains resolved findings that have not been cleaned up.",
    ),
    cross_file: bool = typer.Option(
        True,
        "--cross-file/--no-cross-file",
        help="Enable cross-file import graph and service-layer taint propagation (enabled by default).",
    ),
) -> None:
    """Scan Python files or directories for concurrency vulnerabilities."""
    start_time = time.perf_counter()
    try:
        config = load_cguard_config(start_path=path, config_path=config_file)
    except (FileNotFoundError, ValueError) as err:
        raise typer.BadParameter(str(err), param_hint="--config") from err

    # CLI flag precedence overrides config file settings
    cli_selected = _parse_cli_rules(select_rules)
    if cli_selected:
        config.select = cli_selected
        config.ignore = [r for r in config.ignore if r not in cli_selected]

    cli_ignored = _parse_cli_rules(ignore_rules)
    if cli_ignored:
        config.ignore = list(dict.fromkeys(config.ignore + cli_ignored))

    if confidence is not None:
        config.confidence = confidence.lower()

    if jobs is not None:
        config.jobs = jobs
    elif workers is not None:
        config.jobs = workers

    config.cross_file = cross_file

    py_files = discover_python_files(path, config=config)
    effective_rules = rules or (path.parent / config.rules_file if config.rules_file and path.is_file() else path / config.rules_file if config.rules_file else None)
    try:
        custom_rules = load_yaml_rules(effective_rules) if effective_rules else None
    except (OSError, ValueError, RuntimeError) as error:
        raise typer.BadParameter(str(error), param_hint="--rules") from error

    changed_files: Optional[set[Path]] = None
    if changed_only or base_ref:
        repo_dir = path if path.is_dir() else path.parent
        changed_files = get_changed_python_files(repo_dir, base_ref=base_ref)
        if changed_files is not None:
            py_files = [f for f in py_files if f in changed_files or f.resolve() in changed_files]

    cache_mgr: Optional[Any] = None
    target_cache_dir = cache_dir or DEFAULT_CACHE_DIR
    rules_hash = compute_rules_hash(rules_path=effective_rules, custom_rules=custom_rules, config=config)

    if clear_cache:
        FileCache(cache_dir=target_cache_dir, enabled=True).clear()
        if cache_path is not None:
            CacheManager(
                cache_db_path=cache_path,
                scanner_version=__version__,
                rules_hash=rules_hash,
            ).clear_cache()

    if cache and config.cache:
        if cache_path is not None:
            cache_mgr = CacheManager(
                cache_db_path=cache_path,
                scanner_version=__version__,
                rules_hash=rules_hash,
            )
        else:
            cache_mgr = FileCache(
                cache_dir=target_cache_dir,
                version=__version__,
                ignore_pragma=ignore_pragma,
                rules_hash=rules_hash,
                enabled=True,
            )

    chosen_jobs = jobs if jobs is not None else workers
    if chosen_jobs is None or chosen_jobs == 0:
        effective_jobs = os.cpu_count() or 4
    else:
        effective_jobs = max(1, chosen_jobs)

    suppression_filter = SuppressionFilter(ignore_pragma=ignore_pragma)
    findings = scan_project(
        py_files,
        roots=[path] if path.is_dir() else [path.parent],
        custom_rules=custom_rules,
        cache_manager=cache_mgr,
        suppression_filter=suppression_filter,
        workers=workers,
        jobs=effective_jobs,
        config=config,
        cross_file=cross_file,
    )
    if config.select:
        findings = [finding for finding in findings if finding.rule_id in config.select]
    elif config.ignore:
        findings = [finding for finding in findings if finding.rule_id not in config.ignore]

    eff_conf = (confidence or config.confidence or "low").upper()
    if eff_conf not in {"HIGH", "MEDIUM", "LOW"}:
        raise typer.BadParameter("confidence must be one of: high, medium, low", param_hint="--confidence")
    allowed_conf = (
        {"HIGH"}
        if eff_conf == "HIGH"
        else ({"HIGH", "MEDIUM"} if eff_conf == "MEDIUM" else {"HIGH", "MEDIUM", "LOW"})
    )
    findings = [f for f in findings if (f.confidence or "HIGH").upper() in allowed_conf]

    if changed_files is not None:
        findings = [f for f in findings if Path(f.filename).resolve() in changed_files]
        py_files = [p for p in py_files if p.resolve() in changed_files]

    if cache_mgr is not None and path.is_dir() and hasattr(cache_mgr, "purge_stale_entries"):
        cache_mgr.purge_stale_entries(set(py_files))

    effective_baseline_path: Optional[Path] = baseline
    if effective_baseline_path is None and config.baseline:
        cfg_base = Path(config.baseline)
        if not cfg_base.is_absolute():
            base_dir = config.config_source.parent if config.config_source else (path if path.is_dir() else path.parent)
            cfg_base = (base_dir / config.baseline).resolve()
        effective_baseline_path = cfg_base

    baseline_result: Optional[BaselineFilterResult] = None
    if effective_baseline_path is not None:
        if not effective_baseline_path.is_file():
            raise typer.BadParameter(f"Baseline file not found: {effective_baseline_path}", param_hint="--baseline")
        loaded_baseline = Baseline.load(effective_baseline_path)
        workspace_root = path if path.is_dir() else path.parent
        baseline_result = filter_with_baseline(findings, loaded_baseline, root_dir=workspace_root)

        if update_baseline:
            update_baseline_file(
                effective_baseline_path,
                baseline_result.baselined_findings,
                root_dir=workspace_root,
                cguard_version=__version__,
            )

        findings_to_report = baseline_result.new_findings
    else:
        findings_to_report = findings

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    elapsed_s = elapsed_ms / 1000.0
    suppressed_count = suppression_filter.suppressed_count
    suppressed_text = f" ({suppressed_count} suppressed)" if suppressed_count > 0 else ""

    cache_hits = getattr(cache_mgr, "hits", 0) if cache_mgr is not None else 0
    cache_misses = max(0, len(py_files) - cache_hits)

    telemetry_summary = (
        f"Scanned {len(py_files)} file(s) ({cache_hits} cached, {cache_misses} parsed across {effective_jobs} worker(s)) "
        f"in {elapsed_s:.2f}s | Found {len(findings_to_report)} issue(s){suppressed_text}"
    )
    if baseline_result is not None:
        telemetry_summary += f" | {baseline_result.summary_footer}"

    has_fail = bool(findings_to_report) or (
        fail_on_stale_baseline and baseline_result is not None and baseline_result.total_resolved > 0
    )

    if format.lower() == "sarif" or (output is not None and output.suffix.lower() == ".sarif"):
        sarif_text = serialize_sarif(
            findings_to_report,
            workspace_root=path if path.is_dir() else path.parent,
        )
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(output, sarif_text)
        else:
            typer.echo(sarif_text)
        raise typer.Exit(code=1 if has_fail else 0)

    if format.lower() == "json" or (output is not None and output.suffix.lower() == ".json"):
        payload = {
            "scanned_files": len(py_files),
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "workers": effective_jobs,
            "elapsed_ms": round(elapsed_ms, 2),
            "findings_count": len(findings_to_report),
            "suppressed_count": suppressed_count,
            "baseline": {
                "baselined_count": baseline_result.total_baselined,
                "new_count": baseline_result.total_new,
                "resolved_count": baseline_result.total_resolved,
                "summary": baseline_result.summary_footer,
            }
            if baseline_result
            else None,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "filename": f.filename,
                    "lineno": f.lineno,
                    "col_offset": getattr(f, "col_offset", None),
                    "function_name": f.function_name,
                    "message": f.message,
                    "suggested_fix_hint": f.suggested_fix_hint,
                    "confidence": f.confidence,
                }
                for f in findings_to_report
            ],
        }
        json_text = json.dumps(payload, indent=2)
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(output, json_text)
        else:
            typer.echo(json_text)
        raise typer.Exit(code=1 if has_fail else 0)

    if format.lower() != "table":
        raise typer.BadParameter("format must be one of: table, json, sarif", param_hint="--format")

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        summary_lines = [
            f"[{f.rule_id}] {f.filename}:{f.lineno} {f.function_name}: {f.message} (Fix: {f.suggested_fix_hint})"
            for f in findings_to_report
        ]
        output.write_text("\n".join(summary_lines) + ("\n" if summary_lines else ""), encoding="utf-8")

    if findings_to_report:
        table = Table(
            title="Concurrency Guard - AST Vulnerability Findings",
            show_header=True,
            header_style="bold red",
        )
        table.add_column("Rule ID", style="bold yellow")
        table.add_column("Confidence", style="bold cyan")
        table.add_column("File:Line", style="cyan")
        table.add_column("Function", style="magenta")
        table.add_column("Vulnerability Description", style="white")
        table.add_column("Fix Hint", style="green")

        for f in findings_to_report:
            table.add_row(
                f.rule_id,
                f.confidence,
                f"{f.filename}:{f.lineno}",
                f.function_name,
                f.message,
                f.suggested_fix_hint,
            )

        console.print(table)
        footer_block = f"\n[bold yellow]{baseline_result.summary_footer}[/bold yellow]" if baseline_result else ""
        console.print(
            Panel(
                f"[bold red]Found {len(findings_to_report)} concurrency vulnerability issue(s){suppressed_text}.[/bold red]\n"
                f"[dim]{telemetry_summary}[/dim]{footer_block}",
                border_style="red",
            )
        )
        if baseline_result:
            console.print(f"[bold]{baseline_result.summary_footer}[/bold]")
        raise typer.Exit(code=1)

    if fail_on_stale_baseline and baseline_result is not None and baseline_result.total_resolved > 0:
        console.print(
            Panel(
                f"[bold red]Strict CI failure: baseline contains {baseline_result.total_resolved} resolved finding(s) that must be cleaned up (--fail-on-stale-baseline).[/bold red]\n"
                f"[dim]{telemetry_summary}[/dim]\n"
                f"[bold yellow]{baseline_result.summary_footer}[/bold yellow]",
                border_style="red",
            )
        )
        console.print(f"[bold]{baseline_result.summary_footer}[/bold]")
        raise typer.Exit(code=1)

    footer_block = f"\n[bold cyan]{baseline_result.summary_footer}[/bold cyan]" if baseline_result else ""
    console.print(
        Panel(
            f"[bold green]All AST concurrency checks passed. No vulnerabilities found{suppressed_text}.[/bold green]\n"
            f"[dim]{telemetry_summary}[/dim]{footer_block}",
            border_style="green",
        )
    )
    if baseline_result:
        console.print(f"[bold]{baseline_result.summary_footer}[/bold]")
    raise typer.Exit(code=0)


@app.command()
def verify(
    file_path: Path = typer.Argument(
        ...,
        exists=True,
        help="File containing FastAPI application to verify with concurrent barrier workers",
    ),
    function: Optional[str] = typer.Option(
        None,
        "--function",
        "-f",
        help="Specific function name to verify (e.g. 'withdraw', 'reserve_stock'). Defaults to all.",
    ),
    workers: int = typer.Option(
        20,
        "--workers",
        "-w",
        help="Number of concurrent workers synchronized at the barrier",
    ),
    headless: bool = typer.Option(
        False,
        "--headless",
        help="Stress a raw Python function in-memory instead of discovering HTTP routes",
    ),
) -> None:
    """Verify runtime concurrency and race condition invariants using asyncio.Barrier.

    Dynamically discovers FastAPI routes, synthesizes Pydantic payloads,
    seeds SQLAlchemy models, and fires concurrent barrier-synchronized requests.
    """
    if headless:
        if function is None:
            raise typer.BadParameter("--function is required with --headless", param_hint="--function")
        try:
            headless_result = verify_function(file_path, function, workers)
        except (OSError, ValueError, ImportError) as error:
            raise typer.BadParameter(str(error), param_hint="file_path") from error
        status = "[bold red]INVARIANT VIOLATION PROVEN[/bold red]" if headless_result["invariant_violated"] else "[bold green]INVARIANT HELD[/bold green]"
        console.print(
            Panel(
                f"[bold]Function:[/bold] {headless_result['function_name']}\n"
                f"[bold]Execution mode:[/bold] {headless_result['execution_mode']}\n"
                f"[bold]Barrier workers:[/bold] {headless_result['workers']}\n"
                f"[bold]Observed state:[/bold] {headless_result['state_name']}[{headless_result['key']!r}]\n"
                f"[bold]Completed workers:[/bold] {headless_result['completed_workers']}\n"
                f"[bold]Expected value:[/bold] {headless_result['expected_value']}\n"
                f"[bold]Actual value:[/bold] {headless_result['actual_value']}\n\n{status}",
                title="Headless Runtime Verification",
                border_style="red" if headless_result["invariant_violated"] else "green",
            )
        )
        raise typer.Exit(code=1 if headless_result["invariant_violated"] else 0)

    results: list[DynamicBarrierResult] = asyncio.run(
        run_dynamic_barrier_verification(
            file_path=file_path,
            function_name=function,
            workers=workers,
            initial_quota=50,
        )
    )

    if not results:
        console.print(
            Panel(
                f"[bold yellow]No verifiable POST/PUT/PATCH routes with state mutation found in {file_path}.[/bold yellow]",
                border_style="yellow",
            )
        )
        raise typer.Exit(code=0)

    any_violated = False

    for result in results:
        if result["invariant_violated"]:
            any_violated = True
            proof_text = (
                f"[bold]Target File:[/bold] {file_path}\n"
                f"[bold]Target Endpoint:[/bold] {result['endpoint_path']}\n"
                f"[bold]Function:[/bold] {result['function_name']}\n"
                f"[bold]Mutated Field:[/bold] {result['mutated_field']}\n"
                f"[bold]Synthesized Payload:[/bold] {result['synthesized_payload']}\n"
                f"[bold]Concurrent Barrier Workers:[/bold] {result['workers']}\n"
                f"[bold]Initial {result['mutated_field']}:[/bold] {result['initial_balance']}\n"
                f"[bold]Successful Concurrent Requests:[/bold] "
                f"[bold red]{result['success_count']}[/bold red]\n"
                f"[bold]Final {result['mutated_field']}:[/bold] "
                f"[bold red]{result['final_balance']}[/bold red]\n\n"
                f"[bold red]INVARIANT VIOLATION PROVEN:[/bold red]\n"
                f"Multiple concurrent requests succeeded against {result['mutated_field']}="
                f"{result['initial_balance']} due to an unlocked Read-Modify-Write race condition "
                f"(CG-001).\n"
                f"Expected max 1 successful request, but {result['success_count']} succeeded!"
            )
            console.print(
                Panel(
                    proof_text,
                    title=f"[bold red]❌ RACE PROVEN: {result['endpoint_path']}[/bold red]",
                    border_style="red",
                )
            )
        else:
            safe_text = (
                f"[bold]Target File:[/bold] {file_path}\n"
                f"[bold]Target Endpoint:[/bold] {result['endpoint_path']}\n"
                f"[bold]Function:[/bold] {result['function_name']}\n"
                f"[bold]Mutated Field:[/bold] {result['mutated_field']}\n"
                f"[bold]Synthesized Payload:[/bold] {result['synthesized_payload']}\n"
                f"[bold]Concurrent Barrier Workers:[/bold] {result['workers']}\n"
                f"[bold]Successful Requests:[/bold] {result['success_count']}\n"
                f"[bold]Final {result['mutated_field']}:[/bold] {result['final_balance']}\n\n"
                f"[bold green]Row-level locking preserved the concurrency invariant "
                f"under barrier stress.[/bold green]"
            )
            console.print(
                Panel(
                    safe_text,
                    title=f"[bold green]✔ INVARIANT HELD: {result['endpoint_path']}[/bold green]",
                    border_style="green",
                )
            )

    raise typer.Exit(code=1 if any_violated else 0)


def _combine_reproducers(traces: list[InterleavingTrace], workers: int = 2) -> str:
    """Combine multiple reproducer test scripts into a single clean pytest module."""
    if not traces:
        return '"""ConcurrencyGuard Chaos Suite: 0 race conditions found to simulate."""\n'
    if len(traces) == 1:
        return traces[0].reproducer_code

    header = (
        '"""Deterministic Async Chaos Test Suite (Multi-Finding).\n\n'
        'Auto-generated by ConcurrencyGuard (cguard) v3.2.0.\n'
        '"""\n\n'
        'from __future__ import annotations\n\n'
        'import asyncio\n'
        'import pytest\n\n'
    )
    body_parts: list[str] = []
    for i, t in enumerate(traces, start=1):
        code = t.reproducer_code
        stripped = code.strip()
        if stripped.startswith('"""'):
            parts = stripped.split('"""', 2)
            if len(parts) >= 3:
                stripped = parts[2].strip()
        lines = [
            ln
            for ln in stripped.splitlines()
            if not ln.startswith("from __future__")
            and not ln.startswith("import ")
            and not ln.startswith("from ")
        ]
        body_parts.append(
            f"# --- Finding #{i}: {t.function_name} ({t.rule_id}) ---\n"
            + "\n".join(lines).strip()
        )

    combined = header + "\n\n".join(body_parts) + "\n"
    ast.parse(combined)
    return combined


@app.command()
def simulate(
    path: Path = typer.Argument(
        Path("."),
        exists=True,
        help="File or directory containing concurrency findings to simulate.",
    ),
    rule: Optional[list[str]] = typer.Option(
        None,
        "--rule",
        "-r",
        help="Filter simulation to specific rule IDs (defaults to CG-001, CG-002, CG-004).",
    ),
    workers: int = typer.Option(
        2,
        "--workers",
        "-w",
        help="Number of concurrent coroutines to simulate in the interleaving trace.",
    ),
    export_test: Optional[Path] = typer.Option(
        None,
        "--export-test",
        help="Destination path to export runnable pytest async chaos test suite.",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: 'table' or 'json'.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to dedicated configuration file (.cguard.toml, cguard.toml, or pyproject.toml).",
    ),
) -> None:
    """Simulate deterministic multi-coroutine async interleavings and state corruption."""
    try:
        config = load_cguard_config(start_path=path, config_path=config_file)
    except (FileNotFoundError, ValueError) as err:
        raise typer.BadParameter(str(err), param_hint="--config") from err

    cli_rules = _parse_cli_rules(rule)
    target_rules = set(cli_rules) if cli_rules else {"CG-001", "CG-002", "CG-004"}

    py_files = discover_python_files(path, config=config)
    effective_rules = (
        path.parent / config.rules_file
        if config.rules_file and path.is_file()
        else path / config.rules_file
        if config.rules_file
        else None
    )
    custom_rules = load_yaml_rules(effective_rules) if effective_rules else None

    suppression_filter = SuppressionFilter()
    all_findings = scan_project(
        py_files,
        roots=[path] if path.is_dir() else [path.parent],
        custom_rules=custom_rules,
        cache_manager=None,
        suppression_filter=suppression_filter,
        jobs=1,
        config=config,
    )

    simulatable = [f for f in all_findings if f.rule_id in target_rules]

    if not simulatable:
        if format.lower() == "json":
            typer.echo(json.dumps({"simulated_findings": 0, "traces": []}, indent=2))
        else:
            console.print(
                Panel(
                    f"[bold green]No race conditions found to simulate in {path}.[/bold green]\n"
                    f"[dim]All scanned endpoints appear protected against {', '.join(sorted(target_rules))}.[/dim]",
                    border_style="green",
                )
            )
        if export_test is not None:
            export_test.parent.mkdir(parents=True, exist_ok=True)
            export_test.write_text(
                '"""ConcurrencyGuard Chaos Suite: 0 race conditions found to simulate."""\n',
                encoding="utf-8",
            )
        raise typer.Exit(code=0)

    traces: list[InterleavingTrace] = []
    for f in simulatable:
        t = simulate_finding(f, workers=workers)
        traces.append(t)

    if export_test is not None:
        export_test.parent.mkdir(parents=True, exist_ok=True)
        combined_code = _combine_reproducers(traces, workers=workers)
        export_test.write_text(combined_code, encoding="utf-8")

    if format.lower() == "json":
        payload = {
            "simulated_findings": len(traces),
            "traces": [t.to_dict() for t in traces],
        }
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(code=0)

    if format.lower() != "table":
        raise typer.BadParameter("format must be one of: table, json", param_hint="--format")

    for idx, t in enumerate(traces, start=1):
        table = Table(
            title=f"Async Interleaving Schedule #{idx}: {t.function_name} ({t.rule_id})",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Time", style="bold yellow", width=8)
        table.add_column("Worker / Thread", style="bold cyan", width=18)
        table.add_column("Action", style="bold white", width=22)
        table.add_column("Code Expression", style="dim white")
        table.add_column("State & Event Description", style="green")

        for event in t.timeline:
            table.add_row(
                f"t={event.time_ms}ms",
                event.worker,
                event.action,
                event.code,
                event.state_description,
            )

        console.print(table)

        if t.anomaly:
            proof_text = (
                f"[bold red]ANOMALY DETECTED: {t.anomaly.anomaly_type}[/bold red]\n"
                f"[bold]Initial State:[/bold]  {t.anomaly.initial_state}\n"
                f"[bold]Expected State:[/bold] {t.anomaly.expected_state}\n"
                f"[bold red]Actual State:[/bold red]   {t.anomaly.actual_state}\n"
                f"[bold yellow]Root Cause:[/bold yellow]     {t.anomaly.root_cause}"
            )
            console.print(Panel(proof_text, border_style="red", title="Empirical Chaos Proof"))

    if export_test is not None:
        console.print(
            Panel(
                f"[bold green]✔ Successfully exported runnable pytest chaos suite to {export_test}[/bold green]\n"
                f"[dim]Run 'pytest {export_test}' to execute the deterministic race interleaving.[/dim]",
                border_style="green",
            )
        )

    raise typer.Exit(code=0)


@app.command("gh-review")
def gh_review(
    path: Path = typer.Argument(
        Path("."),
        exists=True,
        help="Repository root or target directory/file containing Python files to scan.",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        "-t",
        help="GitHub Personal Access Token or GITHUB_TOKEN secret.",
    ),
    repo: Optional[str] = typer.Option(
        None,
        "--repo",
        "-r",
        help="Target GitHub repository in 'owner/repo' format (defaults to GITHUB_REPOSITORY).",
    ),
    pr: Optional[int] = typer.Option(
        None,
        "--pr",
        "-p",
        help="Target Pull Request number (auto-detected from CI environment if omitted).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview GitHub review payload and markdown suggestion blocks without making API requests.",
    ),
    base_ref: Optional[str] = typer.Option(
        None,
        "--base-ref",
        "-b",
        help="Base git reference to diff against (e.g. origin/main).",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to dedicated configuration file (.cguard.toml, cguard.toml, or pyproject.toml).",
    ),
) -> None:
    """Post inline GitHub PR review comments with one-click LibCST suggestion blocks."""
    env = detect_github_environment()
    effective_token = token or env.get("token")
    effective_repo = repo or env.get("repo")
    env_pr = env.get("pr_number")
    effective_pr = pr or (int(env_pr) if env_pr is not None else None)
    commit_sha = env.get("commit_sha")

    # If running outside GitHub Actions PR context without required params, exit gracefully
    if not dry_run and (not effective_token or not effective_repo or not effective_pr):
        console.print(
            Panel(
                "[yellow]Warning: GITHUB_TOKEN, GITHUB_REPOSITORY, or PR number not detected.\n"
                "Skipping PR review comment posting (running outside a GitHub Actions Pull Request context).[/yellow]",
                border_style="yellow",
                title="GitHub Review Bot",
            )
        )
        raise typer.Exit(code=0)

    try:
        config = load_cguard_config(start_path=path, config_path=config_file)
    except (FileNotFoundError, ValueError) as err:
        raise typer.BadParameter(str(err), param_hint="--config") from err

    py_files = discover_python_files(path, config=config)
    effective_rules = (
        path.parent / config.rules_file
        if config.rules_file and path.is_file()
        else path / config.rules_file
        if config.rules_file
        else None
    )
    custom_rules = load_yaml_rules(effective_rules) if effective_rules else None

    suppression_filter = SuppressionFilter()
    all_findings = scan_project(
        py_files,
        roots=[path] if path.is_dir() else [path.parent],
        custom_rules=custom_rules,
        cache_manager=None,
        suppression_filter=suppression_filter,
        jobs=1,
        config=config,
    )

    if not all_findings:
        console.print(
            Panel(
                f"[bold green]No concurrency findings detected in {path}. Clean pull request![/bold green]",
                border_style="green",
                title="GitHub Review Bot",
            )
        )
        raise typer.Exit(code=0)

    # Obtain unified diff
    repo_root = path if path.is_dir() else path.parent
    diff_text = get_pr_diff(repo_root, base_ref=base_ref)
    if not diff_text and effective_token and effective_repo and effective_pr:
        try:
            diff_text = fetch_pr_diff(effective_repo, effective_pr, effective_token)
        except urllib.error.HTTPError:
            diff_text = ""

    candidate_comments: list[ReviewComment] = []
    for f in all_findings:
        target_path = str(f.filename)
        target_line = f.lineno

        if diff_text:
            pos = map_finding_to_pr_diff(f, diff_text, repo_root=repo_root)
            if pos is None:
                if not dry_run:
                    # In live PR mode, GitHub only allows comments on lines inside the PR diff
                    continue
                target_path = str(f.filename)
                target_line = f.lineno
            else:
                target_path = pos.path
                target_line = pos.line

        body = format_suggestion_comment(f)
        candidate_comments.append(
            ReviewComment(
                path=target_path,
                line=target_line,
                body=body,
                commit_id=commit_sha,
            )
        )

    if not candidate_comments:
        console.print(
            Panel(
                "[bold green]All detected findings fall outside the PR diff changes. Zero comments required.[/bold green]",
                border_style="green",
                title="GitHub Review Bot",
            )
        )
        raise typer.Exit(code=0)

    if dry_run:
        console.print(
            Panel(
                f"[bold cyan]ConcurrencyGuard PR Inline Review Bot (Dry-Run Mode)[/bold cyan]\n"
                f"Target Repository: [bold]{effective_repo or 'local/preview'}[/bold] | PR: #{effective_pr or 'N/A'}\n"
                f"Total Comments to Dispatch: {len(candidate_comments)}",
                border_style="cyan",
                title="GitHub Review Bot Preview",
            )
        )
        for idx, c in enumerate(candidate_comments, start=1):
            console.print(
                Panel(
                    f"[bold magenta]Target File & Line: {c.path}:{c.line}[/bold magenta]\n\n{c.body}",
                    title=f"Review Comment #{idx}",
                    border_style="blue",
                )
            )
        typer.echo(json.dumps([c.to_dict() for c in candidate_comments], indent=2))
        raise typer.Exit(code=0)

    # Live execution: check existing comments for idempotency
    assert effective_token is not None
    assert effective_repo is not None
    assert effective_pr is not None

    try:
        existing = fetch_existing_pr_comments(effective_repo, effective_pr, effective_token)
    except urllib.error.HTTPError as err:
        console.print(f"[bold red]GitHub API Error fetching existing comments: HTTP {err.code} - {err.reason}[/bold red]")
        raise typer.Exit(code=1) from err
    except urllib.error.URLError as err:
        console.print(f"[bold red]Network connection error: {err.reason}[/bold red]")
        raise typer.Exit(code=1) from err

    posted_count = 0
    skipped_count = 0

    for comment in candidate_comments:
        if is_duplicate_comment(comment, existing):
            skipped_count += 1
            continue

        try:
            post_pr_review_comment(effective_repo, effective_pr, comment, effective_token)
            posted_count += 1
        except urllib.error.HTTPError as err:
            console.print(
                f"[bold red]GitHub API Error posting comment to {comment.path}:{comment.line}: HTTP {err.code} - {err.reason}[/bold red]"
            )
            raise typer.Exit(code=1) from err
        except urllib.error.URLError as err:
            console.print(f"[bold red]Network error posting comment: {err.reason}[/bold red]")
            raise typer.Exit(code=1) from err

    console.print(
        Panel(
            f"[bold green]✔ Successfully processed PR #{effective_pr}[/bold green]\n"
            f"Posted: [bold]{posted_count}[/bold] review comments | Skipped (idempotent): [dim]{skipped_count}[/dim]",
            border_style="green",
            title="GitHub Review Bot Complete",
        )
    )
    raise typer.Exit(code=0)


@app.command()
def fix(
    file_path: Path = typer.Argument(
        ...,
        exists=True,
        help="Target Python file or directory to auto-patch with concurrency fixes",
    ),
    rule: Optional[list[str]] = typer.Option(
        None,
        "--rule",
        "-r",
        help="Specific rule(s) to fix (e.g. CG-001, CG-006). Repeatable or comma-separated.",
    ),
    write: bool = typer.Option(
        False,
        "--write",
        help="Write the patched code back to disk",
    ),
    diff: bool = typer.Option(
        False,
        "--diff",
        help="Print unified diff of changes without modifying files on disk unless --write is set",
    ),
    check: bool = typer.Option(
        False,
        "--check",
        help="Dry-run check mode. Exit 1 if files would be modified, 0 otherwise.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print unified diff of changes without modifying files on disk",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: 'text' or 'json'",
    ),
    changed_only: bool = typer.Option(
        False,
        "--changed-only",
        help="Only patch files that have git changes.",
    ),
    base_ref: Optional[str] = typer.Option(
        None,
        "--base-ref",
        help="Git base reference (e.g. origin/main, main) to check for changes.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to dedicated configuration file (.cguard.toml, cguard.toml, or pyproject.toml).",
    ),
) -> None:
    """Auto-patch concurrency race conditions and idempotency bugs using LibCST."""
    format_clean = format.lower()
    if format_clean not in ("text", "json"):
        raise typer.BadParameter("format must be one of: text, json", param_hint="--format")

    try:
        config = load_cguard_config(start_path=file_path, config_path=config_file)
    except (FileNotFoundError, ValueError) as err:
        raise typer.BadParameter(str(err), param_hint="--config") from err

    if file_path.is_dir():
        target_files = discover_python_files(file_path, config=config)
    else:
        target_files = [] if config.is_path_excluded(file_path) else [file_path]

    changed_files: Optional[set[Path]] = None
    if changed_only or base_ref:
        repo_dir = file_path if file_path.is_dir() else file_path.parent
        changed_files = get_changed_python_files(repo_dir, base_ref=base_ref)

    rules_filter: Optional[set[str]] = None
    if rule:
        rules_filter = set()
        items = [rule] if isinstance(rule, str) else rule
        for item in items:
            for r in item.split(","):
                cleaned = r.strip().upper()
                if cleaned:
                    rules_filter.add(cleaned)

    diff_gen = DiffGenerator(rules=rules_filter)

    show_diff = diff or dry_run
    # --check guarantees zero disk modification
    # --diff without --write is also dry-run preview by default
    should_write = write and not check and not dry_run
    is_dry_run = not should_write

    total_patched_files = 0
    would_modify_count = 0
    any_preflight_failed = False
    json_files: list[dict[str, Any]] = []

    rule_descriptions = {
        "CG-001": "Appended .with_for_update() row lock to query",
        "CG-002": "Injected idempotency_key: str = Header(...) parameter",
        "CG-004": "Wrapped commit in try/except IntegrityError with rollback",
        "CG-006": "Wrapped async shared-state mutation in asyncio.Lock",
        "CG-007": "Wrapped threaded shared-state mutation in threading.Lock",
        "CG-009": "Wrapped concurrent file write in FileLock",
        "CG-016": "Added Django select_for_update() to ORM fetch",
        "CG-017": "Replaced in-memory arithmetic with atomic database F() expression",
        "CG-022": "Wrapped premature task dispatch in transaction.on_commit()",
        "CG-025": "Replaced blocking time.sleep() with await asyncio.sleep()",
        "CG-033": "Preserved asyncio cancellation in broad exception handlers",
    }

    for target in target_files:
        if changed_files is not None and target.resolve() not in changed_files:
            if len(target_files) == 1 and format_clean != "json":
                console.print(f"[dim]Skipping {target}: not changed in git.[/dim]")
            continue

        try:
            source_code = target.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue

        initial_findings = scan_file(target)

        try:
            rel_path = str(target.relative_to(Path.cwd()))
        except (ValueError, TypeError, OSError):
            rel_path = str(target).lstrip("/")

        fromfile = f"a/{rel_path}"
        tofile = f"b/{rel_path}"

        diff_result = diff_gen.generate_diff(
            source_code,
            filepath=target,
            fromfile=fromfile,
            tofile=tofile,
        )

        if not diff_result.is_valid:
            any_preflight_failed = True
            if format_clean == "json":
                json_files.append({
                    "file": str(target),
                    "modified": False,
                    "diff": "",
                    "fixed_rules": [],
                    "skipped": [],
                    "is_valid": False,
                    "error_message": diff_result.error_message,
                })
            else:
                console.print(
                    Panel(
                        f"[bold red]❌ Preflight syntax validation failed for {target}:[/bold red]\n"
                        f"[red]{diff_result.error_message}[/red]\n"
                        "[yellow]Patch discarded. File was not modified.[/yellow]",
                        title="[bold red]Patch Rejected[/bold red]",
                        border_style="red",
                    )
                )
            continue

        patched_code = diff_result.patched_code
        is_modified = (source_code != patched_code)
        if is_modified:
            would_modify_count += 1

        # Determine which rules were fixed
        remaining_findings = scan_source_code(patched_code, filename=str(target))
        remaining_ids = {f.rule_id for f in remaining_findings}
        fixed_findings = [f for f in initial_findings if f.rule_id not in remaining_ids]

        if format_clean == "json":
            json_files.append({
                "file": str(target),
                "modified": is_modified,
                "diff": diff_result.diff if is_modified else "",
                "fixed_rules": [f.rule_id for f in fixed_findings],
                "skipped": [
                    {
                        "rule_id": s.rule_id,
                        "function": s.function_name,
                        "lineno": s.lineno,
                        "reason": s.reason,
                    }
                    for s in diff_result.skipped
                ],
                "is_valid": True,
                "error_message": None,
            })
            if is_modified and should_write:
                atomic_write_text(target, patched_code)
            continue

        if show_diff:
            if diff_result.diff:
                colored = colorize_diff(diff_result.diff, is_tty=sys.stdout.isatty())
                sys.stdout.write(colored)
                if not colored.endswith("\n"):
                    sys.stdout.write("\n")
            if is_modified and should_write:
                atomic_write_text(target, patched_code)
            continue

        if check and not show_diff:
            if is_modified:
                console.print(f"[bold red]{target}[/bold red] would be modified by cguard fix.")
            continue

        if diff_result.skipped:
            skipped_table = Table(
                title=f"Manual Review Required: {target}",
                show_header=True,
                header_style="bold yellow",
            )
            skipped_table.add_column("Rule ID", style="bold yellow")
            skipped_table.add_column("Function", style="magenta")
            skipped_table.add_column("Line", justify="right")
            skipped_table.add_column("Reason")
            for skipped in diff_result.skipped:
                skipped_table.add_row(skipped.rule_id, skipped.function_name, str(skipped.lineno), skipped.reason)
            console.print(skipped_table)

        if not is_modified:
            if len(target_files) == 1:
                console.print(
                    Panel(
                        f"[bold green]No concurrency fixes needed for {target}.[/bold green]",
                        border_style="green",
                    )
                )
            continue

        total_patched_files += 1

        # Render summary table of patched rules
        summary_table = Table(
            title=f"LibCST Auto-Patch Summary: {target}",
            show_header=True,
            header_style="bold green",
        )
        summary_table.add_column("Rule ID", style="bold yellow")
        summary_table.add_column("Function", style="magenta")
        summary_table.add_column("Fix Applied", style="white")

        seen_fixes: set[tuple[str, str]] = set()
        for f in fixed_findings:
            key = (f.rule_id, f.function_name)
            if key not in seen_fixes:
                seen_fixes.add(key)
                summary_table.add_row(
                    f.rule_id,
                    f.function_name,
                    rule_descriptions.get(f.rule_id, "Applied auto-fix patch"),
                )

        console.print(summary_table)

        diff_str = diff_result.diff
        diff_syntax = Syntax(diff_str, "diff", theme="monokai", line_numbers=True)
        console.print(
            Panel(
                diff_syntax,
                title=f"[bold cyan]LibCST Auto-Patch Preview: {target}[/bold cyan]",
                border_style="cyan",
            )
        )

        if should_write:
            atomic_write_text(target, patched_code)
            console.print(
                Panel(
                    f"[bold green]✔ Successfully wrote patched code to {target}[/bold green]",
                    border_style="green",
                )
            )

    if format_clean == "json":
        all_diff = "".join(f["diff"] for f in json_files if f["diff"])
        json_output = {
            "dry_run": is_dry_run,
            "would_modify_count": would_modify_count,
            "total_files": len(target_files),
            "diff": all_diff,
            "files": json_files,
            "preflight_failed": any_preflight_failed,
        }
        sys.stdout.write(json.dumps(json_output, indent=2) + "\n")
        if check:
            raise typer.Exit(code=1 if (would_modify_count > 0 or any_preflight_failed) else 0)
        raise typer.Exit(code=1 if any_preflight_failed else 0)

    if check and not show_diff:
        if would_modify_count > 0:
            console.print(
                f"[bold red]{would_modify_count} file{'s' if would_modify_count != 1 else ''} would be modified.[/bold red]"
            )
        else:
            console.print(
                "[bold green]No concurrency fixes needed. All files match desired state.[/bold green]"
            )

    if not show_diff and not check:
        if total_patched_files == 0 and len(target_files) > 1:
            console.print(
                Panel(
                    "[bold green]No concurrency fixes needed across scanned files.[/bold green]",
                    border_style="green",
                )
            )
        elif not should_write and total_patched_files > 0:
            console.print(
                Panel(
                    "[dim]Dry-run mode: Pass [bold]--write[/bold] to apply the patch directly to disk.[/dim]",
                    border_style="yellow",
                )
            )

    if check:
        raise typer.Exit(code=1 if (would_modify_count > 0 or any_preflight_failed) else 0)

    raise typer.Exit(code=1 if any_preflight_failed else 0)


@app.command()
def report(
    file_path: Path = typer.Argument(
        Path("."),
        exists=True,
        readable=True,
        help="Target Python file or directory to generate concurrency audit report for",
    ),
    format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Report output format: 'html', 'markdown', or 'json'",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to write the report to (defaults to cguard-report.html for HTML)",
    ),
    min_score: Optional[int] = typer.Option(
        None,
        "--min-score",
        help="Minimum required Concurrency Health Score (0-100) for CI quality gate (exits 1 if score < min-score)",
    ),
    confidence: Optional[str] = typer.Option(
        None,
        "--confidence",
        help="Filter findings by minimum confidence level: 'high', 'medium', or 'low'",
    ),
    ignore_pragma: bool = typer.Option(
        False,
        "--ignore-pragma",
        help="Bypass inline '# cguard: ignore' comments and report all findings",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to pyproject.toml configuration file",
    ),
    jobs: Optional[int] = typer.Option(
        None,
        "--jobs",
        "-j",
        help="Number of worker processes for parallel scanning",
    ),
    workers: Optional[int] = typer.Option(
        None,
        "--workers",
        "-w",
        help="Legacy alias for --jobs or barrier worker count",
    ),
) -> None:
    """Generate an executive concurrency health score and interactive HTML/Markdown audit report."""
    # Backward compatibility with legacy PR barrier report
    if file_path.is_file() and output is not None and str(output).endswith("pr_report.md") and format != "markdown":
        source_code = file_path.read_text(encoding="utf-8")
        findings = scan_file(file_path)

        barrier_result: Optional[BarrierResult] = None
        try:
            module_name = f"cguard_report_target_{file_path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is not None and spec.loader is not None:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                target_app: Any = getattr(module, "app", None)
                if target_app is not None:
                    engine: Any = getattr(module, "engine", None)
                    session_factory: Any = getattr(
                        module, "async_session", getattr(module, "AsyncSessionLocal", None)
                    )
                    wallet_model: Any = getattr(module, "Wallet", None)
                    base_class: Any = getattr(module, "Base", None)
                    base_metadata: Any = getattr(base_class, "metadata", None) if base_class else None

                    has_withdraw_route = any(
                        getattr(route, "path", None) == "/wallet/withdraw"
                        for route in getattr(target_app, "routes", [])
                    )
                    if has_withdraw_route:
                        barrier_result = asyncio.run(
                            run_barrier_test(
                                app=target_app,
                                endpoint="/wallet/withdraw",
                                workers=workers or 20,
                                initial_balance=50,
                                withdraw_amount=50,
                                engine=engine,
                                session_factory=session_factory,
                                wallet_model=wallet_model,
                                base_metadata=base_metadata,
                            )
                        )
        except Exception:  # noqa: BLE001
            barrier_result = None

        patched_code = apply_all_fixes(source_code)
        markdown_report = generate_github_pr_markdown(
            file_path=file_path,
            findings=findings,
            barrier_result=barrier_result,
            patched_code=patched_code if patched_code != source_code else None,
            original_code=source_code,
        )

        atomic_write_text(output, markdown_report)
        console.print(
            Panel(
                f"[bold green]✔ Successfully wrote PR report to {output}[/bold green]",
                border_style="green",
            )
        )
        if findings or (barrier_result and barrier_result.get("invariant_violated")):
            raise typer.Exit(code=1)
        raise typer.Exit(code=0)

    # Executive Concurrency Health Report
    cfg = load_cguard_config(
        start_path=file_path if file_path.is_dir() else file_path.parent,
        config_path=config_file,
    )

    if file_path.is_file():
        py_files = [file_path]
        roots = [file_path.parent]
    else:
        py_files = discover_python_files(file_path, config=cfg)
        roots = [file_path]

    effective_jobs = jobs if jobs is not None else (workers or os.cpu_count() or 4)
    suppression_filter = SuppressionFilter(ignore_pragma=ignore_pragma)

    findings = scan_project(
        py_files,
        roots=roots,
        suppression_filter=suppression_filter,
        jobs=effective_jobs,
        config=cfg,
    )

    if confidence:
        eff_conf = confidence.upper()
        allowed = {"HIGH"} if eff_conf == "HIGH" else ({"HIGH", "MEDIUM"} if eff_conf == "MEDIUM" else {"HIGH", "MEDIUM", "LOW"})
        findings = [f for f in findings if getattr(f, "confidence", "HIGH").upper() in allowed]

    metrics = compute_audit_metrics(findings, scanned_files=py_files)

    fmt = format.lower().strip()
    if fmt == "html":
        content = render_html_report(metrics, findings, scanned_files=py_files)
        target_out = output if output is not None else Path("cguard-report.html")
        atomic_write_text(target_out, content)
        console.print(
            Panel(
                f"[bold green]✔ Executive Concurrency Health Report saved to {target_out}[/bold green]\n"
                f"Health Score: [bold]{metrics.health_score} / 100[/bold] (Grade [bold]{metrics.grade}[/bold]) | "
                f"Findings: {metrics.total_findings} ({metrics.high_count} High) | "
                f"Auto-Fixable: {metrics.auto_fixable_count} | Files: {metrics.files_scanned}",
                border_style="green",
            )
        )
    elif fmt in ("markdown", "md"):
        content = render_markdown_report(metrics, findings)
        if output is not None:
            atomic_write_text(output, content)
            console.print(
                Panel(
                    f"[bold green]✔ Executive Markdown Report saved to {output}[/bold green]",
                    border_style="green",
                )
            )
        else:
            sys.stdout.write(content + "\n")
    elif fmt == "json":
        json_data = json.dumps(metrics.to_dict(), indent=2)
        if output is not None:
            atomic_write_text(output, json_data)
            console.print(
                Panel(
                    f"[bold green]✔ Executive JSON Report saved to {output}[/bold green]",
                    border_style="green",
                )
            )
        else:
            sys.stdout.write(json_data + "\n")
    else:
        raise typer.BadParameter(f"Unknown format: '{format}'. Choose from 'html', 'markdown', or 'json'.")

    # CI Quality Gate Check
    if min_score is not None:
        if metrics.health_score < min_score:
            console.print(
                f"[bold red]✖ CI Quality Gate Failed:[/bold red] Concurrency Health Score {metrics.health_score}/100 "
                f"is below required minimum {min_score}/100 (Grade {metrics.grade})"
            )
            raise typer.Exit(code=1)
        else:
            console.print(
                f"[bold green]✔ CI Quality Gate Passed:[/bold green] Concurrency Health Score {metrics.health_score}/100 "
                f"meets or exceeds required minimum {min_score}/100 (Grade {metrics.grade})"
            )
            raise typer.Exit(code=0)


baseline_app = typer.Typer(
    name="baseline",
    help="Manage ConcurrencyGuard technical debt baselines (.cguard-baseline.json).",
)
app.add_typer(baseline_app, name="baseline")


@baseline_app.command(name="create")
def baseline_create(
    path: Path = typer.Argument(
        Path("."),
        exists=True,
        help="Path to Python file or directory to scan for baseline generation.",
    ),
    output: Path = typer.Option(
        Path(".cguard-baseline.json"),
        "--output",
        "-o",
        help="Destination path for generated .cguard-baseline.json file.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to dedicated configuration file (.cguard.toml, cguard.toml, or pyproject.toml).",
    ),
    select_rules: Optional[list[str]] = typer.Option(
        None,
        "--select-rule",
        "-s",
        help="Whitelist specific rule IDs (e.g. -s CG-001 -s CG-002, or comma-separated).",
    ),
    ignore_rules: Optional[list[str]] = typer.Option(
        None,
        "--ignore-rule",
        "-i",
        help="Ignore specific rule IDs (e.g. -i CG-003, or comma-separated).",
    ),
    confidence: Optional[str] = typer.Option(
        None,
        "--confidence",
        help="Filter findings by minimum confidence level: 'high', 'medium', or 'low'.",
    ),
    rules: Optional[Path] = typer.Option(
        None,
        "--rules",
        help="YAML file containing custom concurrency rules.",
    ),
    ignore_pragma: bool = typer.Option(
        False,
        "--ignore-pragma",
        help="Bypass inline '# cguard: ignore' pragma comments and report all findings.",
    ),
    jobs: Optional[int] = typer.Option(
        None,
        "--jobs",
        "-j",
        help="Number of worker processes for parallel scanning.",
    ),
) -> None:
    """Scan the target codebase and generate a deterministic .cguard-baseline.json snapshot."""
    try:
        config = load_cguard_config(start_path=path, config_path=config_file)
    except (FileNotFoundError, ValueError) as err:
        raise typer.BadParameter(str(err), param_hint="--config") from err

    cli_selected = _parse_cli_rules(select_rules)
    if cli_selected:
        config.select = cli_selected
        config.ignore = [r for r in config.ignore if r not in cli_selected]

    cli_ignored = _parse_cli_rules(ignore_rules)
    if cli_ignored:
        config.ignore = list(dict.fromkeys(config.ignore + cli_ignored))

    if confidence is not None:
        config.confidence = confidence.lower()

    if jobs is not None:
        config.jobs = jobs

    py_files = discover_python_files(path, config=config)
    effective_rules = rules or (path.parent / config.rules_file if config.rules_file and path.is_file() else path / config.rules_file if config.rules_file else None)
    try:
        custom_rules = load_yaml_rules(effective_rules) if effective_rules else None
    except (OSError, ValueError, RuntimeError) as error:
        raise typer.BadParameter(str(error), param_hint="--rules") from error

    suppression_filter = SuppressionFilter(ignore_pragma=ignore_pragma)
    effective_jobs = jobs or os.cpu_count() or 4
    findings = scan_project(
        py_files,
        roots=[path] if path.is_dir() else [path.parent],
        custom_rules=custom_rules,
        cache_manager=None,
        suppression_filter=suppression_filter,
        jobs=effective_jobs,
        config=config,
    )
    if config.select:
        findings = [f for f in findings if f.rule_id in config.select]
    elif config.ignore:
        findings = [f for f in findings if f.rule_id not in config.ignore]

    eff_conf = (confidence or config.confidence or "low").upper()
    allowed_conf = (
        {"HIGH"}
        if eff_conf == "HIGH"
        else ({"HIGH", "MEDIUM"} if eff_conf == "MEDIUM" else {"HIGH", "MEDIUM", "LOW"})
    )
    findings = [f for f in findings if (f.confidence or "HIGH").upper() in allowed_conf]

    workspace_root = path if path.is_dir() else path.parent
    base_obj = create_baseline(
        findings,
        root_dir=workspace_root,
        cguard_version=__version__,
    )
    base_obj.save(output)

    console.print(
        Panel(
            f"[bold green]Created baseline with {len(findings)} finding(s) in {output}[/bold green]\n"
            f"[dim]Scanned {len(py_files)} file(s). All existing findings recorded as technical debt.[/dim]",
            border_style="green",
        )
    )
    raise typer.Exit(code=0)


@app.command()
def lsp(
    stdio: bool = typer.Option(
        True,
        "--stdio/--no-stdio",
        help="Use stdin/stdout for JSON-RPC 2.0 communication (default).",
    ),
) -> None:
    """Start the ConcurrencyGuard Language Server (LSP 3.17) over stdin/stdout.

    Provides real-time AST diagnostics and QuickFix CodeActions for
    VS Code, Cursor, Neovim, and any LSP-compatible editor.
    """
    if not stdio:
        console.print(
            "[bold yellow]Only --stdio mode is currently supported.[/bold yellow]"
        )
        raise typer.Exit(code=1)

    exit_code = run_lsp_server()
    raise typer.Exit(code=exit_code)


@app.command()
def watch(
    path: Path = typer.Argument(
        Path("."),
        exists=True,
        help="Directory or file to watch for Python file changes.",
    ),
    interval: float = typer.Option(
        0.5,
        "--interval",
        "-i",
        help="Polling interval in seconds between file system checks.",
    ),
    once: bool = typer.Option(
        False,
        "--once",
        help="Run a single scan cycle and exit (useful for CI/testing).",
    ),
    max_cycles: Optional[int] = typer.Option(
        None,
        "--max-cycles",
        "-n",
        help="Maximum number of watch cycles before exiting (None = infinite).",
    ),
    auto_fix: bool = typer.Option(
        False,
        "--auto-fix",
        help="Automatically apply LibCST fixes on changed files.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to dedicated configuration file (.cguard.toml, cguard.toml, or pyproject.toml).",
    ),
) -> None:
    """Watch Python files for changes and report concurrency issues in real time.

    Monitors .py files using os.stat mtime + SHA-256 digests and re-scans
    only modified files for near-instant feedback.
    """
    try:
        config = load_cguard_config(start_path=path, config_path=config_file)
    except (FileNotFoundError, ValueError):
        config = None

    if not once and max_cycles is None:
        console.print(
            Panel(
                f"[bold cyan]ConcurrencyGuard File Watcher[/bold cyan]\n"
                f"Watching: [bold]{path}[/bold] | Interval: {interval}s | Auto-fix: {'ON' if auto_fix else 'OFF'}\n"
                f"[dim]Press Ctrl+C to stop.[/dim]",
                border_style="cyan",
            )
        )

    try:
        results = watch_project(
            path,
            interval=interval,
            max_cycles=max_cycles,
            once=once,
            auto_fix=auto_fix,
            config=config,
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Watch mode interrupted.[/bold yellow]")
        raise typer.Exit(code=0) from None

    # Exit code: 1 if any cycle found issues, 0 otherwise
    has_findings = any(r.findings for r in results)
    raise typer.Exit(code=1 if has_findings else 0)


if __name__ == "__main__":
    app()

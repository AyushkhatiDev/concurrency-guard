"""Command line interface for Concurrency Guard."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from concurrency_guard import __version__
from concurrency_guard.cache.file_cache import DEFAULT_CACHE_DIR, FileCache
from concurrency_guard.cache.manager import (
    CacheManager,
    compute_rules_hash,
)
from concurrency_guard.config import load_project_config
from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.patcher.diff_utils import DiffGenerator, colorize_diff
from concurrency_guard.reporter.github_pr import generate_github_pr_markdown
from concurrency_guard.reporter.sarif import findings_to_sarif
from concurrency_guard.runner.barrier_engine import (
    BarrierResult,
    DynamicBarrierResult,
    run_barrier_test,
    run_dynamic_barrier_verification,
)
from concurrency_guard.runner.runtime_verifier import verify_function
from concurrency_guard.scanner.ast_rules import (
    discover_python_files,
    load_yaml_rules,
    scan_file,
    scan_project,
    scan_source_code,
)
from concurrency_guard.scanner.git_filter import get_changed_python_files
from concurrency_guard.scanner.suppression import SuppressionFilter

app = typer.Typer(no_args_is_help=True, help="Deterministic Concurrency & Idempotency Verifier")
console = Console()


@app.callback()
def main() -> None:
    """Deterministic AST + Runtime Concurrency & Idempotency Verifier."""


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
) -> None:
    """Scan Python files or directories for concurrency vulnerabilities."""
    start_time = time.perf_counter()
    config = load_project_config(path)
    py_files = [item for item in discover_python_files(path) if not any(pattern in item.parts or str(item).endswith(pattern) for pattern in config.exclude)]
    effective_rules = rules or (path.parent / config.rules_file if config.rules_file and path.is_file() else path / config.rules_file if config.rules_file else None)
    try:
        custom_rules = load_yaml_rules(effective_rules) if effective_rules else None
    except (OSError, ValueError, RuntimeError) as error:
        raise typer.BadParameter(str(error), param_hint="--rules") from error

    changed_files: Optional[set[Path]] = None
    if changed_only or base_ref:
        repo_dir = path if path.is_dir() else path.parent
        changed_files = get_changed_python_files(repo_dir, base_ref=base_ref)

    cache_mgr: Optional[Any] = None
    target_cache_dir = cache_dir or DEFAULT_CACHE_DIR
    rules_hash = compute_rules_hash(rules_path=effective_rules, custom_rules=custom_rules)

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
    )
    findings = [finding for finding in findings if finding.rule_id not in config.ignore]

    if confidence is not None:
        conf_level = confidence.upper()
        if conf_level not in {"HIGH", "MEDIUM", "LOW"}:
            raise typer.BadParameter("confidence must be one of: high, medium, low", param_hint="--confidence")
        allowed_conf = (
            {"HIGH"}
            if conf_level == "HIGH"
            else ({"HIGH", "MEDIUM"} if conf_level == "MEDIUM" else {"HIGH", "MEDIUM", "LOW"})
        )
        findings = [f for f in findings if f.confidence.upper() in allowed_conf]

    if changed_files is not None:
        findings = [f for f in findings if Path(f.filename).resolve() in changed_files]
        py_files = [p for p in py_files if p.resolve() in changed_files]

    if cache_mgr is not None and path.is_dir() and hasattr(cache_mgr, "purge_stale_entries"):
        cache_mgr.purge_stale_entries(set(py_files))

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    elapsed_s = elapsed_ms / 1000.0
    suppressed_count = suppression_filter.suppressed_count
    suppressed_text = f" ({suppressed_count} suppressed)" if suppressed_count > 0 else ""

    cache_hits = getattr(cache_mgr, "hits", 0) if cache_mgr is not None else 0
    cache_misses = max(0, len(py_files) - cache_hits)

    telemetry_summary = (
        f"Scanned {len(py_files)} file(s) ({cache_hits} cached, {cache_misses} parsed across {effective_jobs} worker(s)) "
        f"in {elapsed_s:.2f}s | Found {len(findings)} issue(s){suppressed_text}"
    )

    if format.lower() == "json":
        payload = {
            "scanned_files": len(py_files),
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "workers": effective_jobs,
            "elapsed_ms": round(elapsed_ms, 2),
            "findings_count": len(findings),
            "suppressed_count": suppressed_count,
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
                for f in findings
            ],
        }
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(code=1 if findings else 0)

    if format.lower() == "sarif":
        typer.echo(json.dumps(findings_to_sarif(findings), indent=2))
        raise typer.Exit(code=1 if findings else 0)

    if format.lower() != "table":
        raise typer.BadParameter("format must be one of: table, json, sarif", param_hint="--format")

    if findings:
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

        for f in findings:
            table.add_row(
                f.rule_id,
                f.confidence,
                f"{f.filename}:{f.lineno}",
                f.function_name,
                f.message,
                f.suggested_fix_hint,
            )

        console.print(table)
        console.print(
            Panel(
                f"[bold red]Found {len(findings)} concurrency vulnerability issue(s){suppressed_text}.[/bold red]\n"
                f"[dim]{telemetry_summary}[/dim]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold green]All AST concurrency checks passed. No vulnerabilities found{suppressed_text}.[/bold green]\n"
            f"[dim]{telemetry_summary}[/dim]",
            border_style="green",
        )
    )
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


@app.command()
def fix(
    file_path: Path = typer.Argument(
        ...,
        exists=True,
        help="Target Python file or directory to auto-patch with concurrency fixes",
    ),
    rule: Optional[str] = typer.Option(
        None,
        "--rule",
        "-r",
        help="Specific rule to fix (e.g. CG-001, CG-006, CG-007, CG-009, CG-016, CG-017). Defaults to all supported rules.",
    ),
    write: bool = typer.Option(
        False,
        "--write",
        help="Write the patched code back to disk",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        "--diff",
        help="Print unified diff of changes without modifying files on disk",
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
) -> None:
    """Auto-patch concurrency race conditions and idempotency bugs using LibCST."""
    config = load_project_config(file_path)
    if file_path.is_dir():
        target_files = [
            f for f in discover_python_files(file_path)
            if not any(pattern in f.parts or str(f).endswith(pattern) for pattern in config.exclude)
        ]
    else:
        target_files = [file_path]

    changed_files: Optional[set[Path]] = None
    if changed_only or base_ref:
        repo_dir = file_path if file_path.is_dir() else file_path.parent
        changed_files = get_changed_python_files(repo_dir, base_ref=base_ref)

    rules_filter = {rule.upper()} if rule else None
    diff_gen = DiffGenerator(rules=rules_filter)

    total_patched_files = 0
    any_preflight_failed = False

    rule_descriptions = {
        "CG-001": "Appended .with_for_update() row lock to query",
        "CG-002": "Injected idempotency_key: str = Header(...) parameter",
        "CG-004": "Wrapped commit in try/except IntegrityError with rollback",
        "CG-006": "Wrapped async shared-state mutation in asyncio.Lock",
        "CG-007": "Wrapped threaded shared-state mutation in threading.Lock",
        "CG-009": "Wrapped concurrent file write in FileLock",
        "CG-016": "Added Django select_for_update() to ORM fetch",
        "CG-017": "Replaced in-memory arithmetic with atomic database F() expression",
    }

    for target in target_files:
        if changed_files is not None and target.resolve() not in changed_files:
            if len(target_files) == 1:
                console.print(f"[dim]Skipping {target}: not changed in git.[/dim]")
            continue

        try:
            source_code = target.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue

        initial_findings = scan_file(target)

        diff_result = diff_gen.generate_diff(
            source_code,
            filepath=target,
            fromfile=str(target),
            tofile=f"{target} (patched)",
        )

        if not diff_result.is_valid:
            console.print(
                Panel(
                    f"[bold red]❌ Preflight syntax validation failed for {target}:[/bold red]\n"
                    f"[red]{diff_result.error_message}[/red]\n"
                    "[yellow]Patch discarded. File was not modified.[/yellow]",
                    title="[bold red]Patch Rejected[/bold red]",
                    border_style="red",
                )
            )
            any_preflight_failed = True
            continue

        patched_code = diff_result.patched_code

        if dry_run:
            if diff_result.diff:
                colored = colorize_diff(diff_result.diff, is_tty=sys.stdout.isatty())
                sys.stdout.write(colored)
                if not colored.endswith("\n"):
                    sys.stdout.write("\n")
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

        if source_code == patched_code:
            if len(target_files) == 1:
                console.print(
                    Panel(
                        f"[bold green]No concurrency fixes needed for {target}.[/bold green]",
                        border_style="green",
                    )
                )
            continue

        total_patched_files += 1

        # Determine which rules were fixed
        remaining_findings = scan_source_code(patched_code, filename=str(target))
        remaining_ids = {f.rule_id for f in remaining_findings}
        fixed_findings = [f for f in initial_findings if f.rule_id not in remaining_ids]

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

        diff = diff_result.diff
        diff_syntax = Syntax(diff, "diff", theme="monokai", line_numbers=True)
        console.print(
            Panel(
                diff_syntax,
                title=f"[bold cyan]LibCST Auto-Patch Preview: {target}[/bold cyan]",
                border_style="cyan",
            )
        )

        if write:
            target.write_text(patched_code, encoding="utf-8")
            console.print(
                Panel(
                    f"[bold green]✔ Successfully wrote patched code to {target}[/bold green]",
                    border_style="green",
                )
            )

    if dry_run:
        raise typer.Exit(code=1 if any_preflight_failed else 0)

    if total_patched_files == 0 and len(target_files) > 1:
        console.print(
            Panel(
                "[bold green]No concurrency fixes needed across scanned files.[/bold green]",
                border_style="green",
            )
        )
    elif not write and total_patched_files > 0:
        console.print(
            Panel(
                "[dim]Dry-run mode: Pass [bold]--write[/bold] to apply the patch directly to disk.[/dim]",
                border_style="yellow",
            )
        )

    raise typer.Exit(code=1 if any_preflight_failed else 0)


@app.command()
def report(
    file_path: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Target Python file to generate Markdown report for",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional path to write the Markdown report to",
    ),
    workers: int = typer.Option(
        20,
        "--workers",
        "-w",
        help="Number of concurrent workers for barrier runtime verification if applicable",
    ),
) -> None:
    """Generate a GitHub Pull Request Markdown report for AST findings and barrier exploit proofs."""
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
                            workers=workers,
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

    if output is not None:
        output.write_text(markdown_report, encoding="utf-8")
        console.print(
            Panel(
                f"[bold green]✔ Successfully wrote PR report to {output}[/bold green]",
                border_style="green",
            )
        )
    else:
        console.print(markdown_report)

    if findings or (barrier_result and barrier_result.get("invariant_violated")):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()

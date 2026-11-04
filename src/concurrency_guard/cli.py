"""Command line interface for Concurrency Guard."""

from __future__ import annotations

import asyncio
import importlib.util
import json
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
from concurrency_guard.cache.manager import (
    DEFAULT_CACHE_FILE,
    CacheManager,
    compute_rules_hash,
)
from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.patcher.diff_utils import DiffGenerator, colorize_diff
from concurrency_guard.reporter.github_pr import generate_github_pr_markdown
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
        help="Output format: 'table' or 'json'",
    ),
    rules: Optional[Path] = typer.Option(None, "--rules", help="YAML file containing custom concurrency rules"),
    cache_path: Optional[Path] = typer.Option(
        None,
        "--cache-path",
        help="Path to SQLite cache database (defaults to .concurrency_guard_cache.db)",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Bypass cache reads and writes completely",
    ),
) -> None:
    """Scan Python files or directories for concurrency vulnerabilities."""
    start_time = time.perf_counter()
    py_files = discover_python_files(path)
    try:
        custom_rules = load_yaml_rules(rules) if rules else None
    except (OSError, ValueError, RuntimeError) as error:
        raise typer.BadParameter(str(error), param_hint="--rules") from error

    cache_mgr: Optional[CacheManager] = None
    if not no_cache:
        db_file = cache_path or DEFAULT_CACHE_FILE
        rules_hash = compute_rules_hash(rules_path=rules, custom_rules=custom_rules)
        cache_mgr = CacheManager(
            cache_db_path=db_file,
            scanner_version=__version__,
            rules_hash=rules_hash,
        )

    suppression_filter = SuppressionFilter()
    findings = scan_project(
        py_files,
        roots=[path] if path.is_dir() else [path.parent],
        custom_rules=custom_rules,
        cache_manager=cache_mgr,
        suppression_filter=suppression_filter,
    )

    if cache_mgr is not None and path.is_dir():
        cache_mgr.purge_stale_entries(set(py_files))

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    suppressed_count = suppression_filter.suppressed_count
    suppressed_text = f" ({suppressed_count} suppressed)" if suppressed_count > 0 else ""

    if format.lower() == "json":
        payload = {
            "scanned_files": len(py_files),
            "elapsed_ms": round(elapsed_ms, 2),
            "findings_count": len(findings),
            "suppressed_count": suppressed_count,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "filename": f.filename,
                    "lineno": f.lineno,
                    "function_name": f.function_name,
                    "message": f.message,
                    "suggested_fix_hint": f.suggested_fix_hint,
                }
                for f in findings
            ],
        }
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(code=1 if findings else 0)

    if findings:
        table = Table(
            title="Concurrency Guard - AST Vulnerability Findings",
            show_header=True,
            header_style="bold red",
        )
        table.add_column("Rule ID", style="bold yellow")
        table.add_column("File:Line", style="cyan")
        table.add_column("Function", style="magenta")
        table.add_column("Vulnerability Description", style="white")
        table.add_column("Fix Hint", style="green")

        for f in findings:
            table.add_row(
                f.rule_id,
                f"{f.filename}:{f.lineno}",
                f.function_name,
                f.message,
                f.suggested_fix_hint,
            )

        console.print(table)
        console.print(
            Panel(
                f"[bold red]Found {len(findings)} concurrency vulnerability issue(s){suppressed_text}.[/bold red]\n"
                f"[dim]Scanned {len(py_files)} file(s) in {elapsed_ms:.1f} ms | Found {len(findings)} issue(s){suppressed_text}[/dim]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold green]All AST concurrency checks passed. No vulnerabilities found{suppressed_text}.[/bold green]\n"
            f"[dim]Scanned {len(py_files)} file(s) in {elapsed_ms:.1f} ms | Found 0 issue(s){suppressed_text}[/dim]",
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
        help="Target Python file to auto-patch with concurrency fixes",
    ),
    rule: Optional[str] = typer.Option(
        None,
        "--rule",
        "-r",
        help="Specific rule to fix (e.g. CG-001, CG-006, CG-007, CG-009, CG-016). Defaults to all supported rules.",
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
) -> None:
    """Auto-patch concurrency race conditions and idempotency bugs using LibCST."""
    source_code = file_path.read_text(encoding="utf-8")
    initial_findings = scan_file(file_path)

    rules_filter = {rule.upper()} if rule else None
    diff_gen = DiffGenerator(rules=rules_filter)
    diff_result = diff_gen.generate_diff(
        source_code,
        filepath=file_path,
        fromfile=str(file_path),
        tofile=f"{file_path} (patched)",
    )

    if not diff_result.is_valid:
        console.print(
            Panel(
                f"[bold red]❌ Preflight syntax validation failed for {file_path}:[/bold red]\n"
                f"[red]{diff_result.error_message}[/red]\n"
                "[yellow]Patch discarded. File was not modified.[/yellow]",
                title="[bold red]Patch Rejected[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    patched_code = diff_result.patched_code

    if dry_run:
        if diff_result.diff:
            colored = colorize_diff(diff_result.diff, is_tty=sys.stdout.isatty())
            sys.stdout.write(colored)
            if not colored.endswith("\n"):
                sys.stdout.write("\n")
        raise typer.Exit(code=0)

    if diff_result.skipped:
        skipped_table = Table(title="Manual Review Required", show_header=True, header_style="bold yellow")
        skipped_table.add_column("Rule ID", style="bold yellow")
        skipped_table.add_column("Function", style="magenta")
        skipped_table.add_column("Line", justify="right")
        skipped_table.add_column("Reason")
        for skipped in diff_result.skipped:
            skipped_table.add_row(skipped.rule_id, skipped.function_name, str(skipped.lineno), skipped.reason)
        console.print(skipped_table)

    if source_code == patched_code:
        console.print(
            Panel(
                f"[bold green]No concurrency fixes needed for {file_path}.[/bold green]",
                border_style="green",
            )
        )
        raise typer.Exit(code=0)

    # Determine which rules were fixed
    remaining_findings = scan_source_code(patched_code, filename=str(file_path))
    remaining_ids = {f.rule_id for f in remaining_findings}
    fixed_findings = [f for f in initial_findings if f.rule_id not in remaining_ids]

    # Render summary table of patched rules
    summary_table = Table(
        title="LibCST Auto-Patch Summary",
        show_header=True,
        header_style="bold green",
    )
    summary_table.add_column("Rule ID", style="bold yellow")
    summary_table.add_column("Function", style="magenta")
    summary_table.add_column("Fix Applied", style="white")

    rule_descriptions = {
        "CG-001": "Appended .with_for_update() row lock to query",
        "CG-002": "Injected idempotency_key: str = Header(...) parameter",
        "CG-004": "Wrapped commit in try/except IntegrityError with rollback",
        "CG-006": "Wrapped async shared-state mutation in asyncio.Lock",
        "CG-007": "Wrapped threaded shared-state mutation in threading.Lock",
        "CG-009": "Wrapped concurrent file write in FileLock",
        "CG-016": "Added Django select_for_update() to ORM fetch",
    }

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
            title=f"[bold cyan]LibCST Auto-Patch Preview: {file_path}[/bold cyan]",
            border_style="cyan",
        )
    )

    if write:
        file_path.write_text(patched_code, encoding="utf-8")
        console.print(
            Panel(
                f"[bold green]✔ Successfully wrote patched code to {file_path}[/bold green]",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                "[dim]Dry-run mode: Pass [bold]--write[/bold] to apply the patch directly to disk.[/dim]",
                border_style="yellow",
            )
        )


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

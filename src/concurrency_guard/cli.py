"""Command line interface for Concurrency Guard."""

from __future__ import annotations

import asyncio
import difflib
import importlib.util
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from concurrency_guard.patcher.cst_fixer import apply_with_for_update_fix
from concurrency_guard.runner.barrier_engine import run_barrier_test
from concurrency_guard.scanner.ast_rules import ASTFinding, scan_file

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
) -> None:
    """Scan Python files or directories for concurrency vulnerabilities."""
    if path.is_dir():
        py_files = sorted(path.rglob("*.py"))
    else:
        py_files = [path]

    findings: list[ASTFinding] = []
    for py_file in py_files:
        findings.extend(scan_file(py_file))

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
                f"[bold red]Found {len(findings)} concurrency vulnerability issue(s).[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    console.print(
        Panel(
            "[bold green]All AST concurrency checks passed. No vulnerabilities found.[/bold green]",
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
    workers: int = typer.Option(
        20,
        "--workers",
        "-w",
        help="Number of concurrent workers synchronized at the barrier",
    ),
) -> None:
    """Verify runtime concurrency and race condition invariants using asyncio.Barrier."""
    module_name = f"cguard_target_{file_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        console.print(f"[bold red]Error: Could not load target module from {file_path}[/bold red]")
        raise typer.Exit(code=2)

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    target_app: Any = getattr(module, "app", None)
    if target_app is None:
        console.print(f"[bold red]Error: No 'app' found in {file_path}[/bold red]")
        raise typer.Exit(code=2)

    engine: Any = getattr(module, "engine", None)
    session_factory: Any = getattr(
        module, "async_session", getattr(module, "AsyncSessionLocal", None)
    )
    wallet_model: Any = getattr(module, "Wallet", None)
    base_class: Any = getattr(module, "Base", None)
    base_metadata: Any = getattr(base_class, "metadata", None) if base_class else None

    # Run barrier stress test
    result = asyncio.run(
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

    if result["invariant_violated"]:
        proof_text = (
            f"[bold]Target File:[/bold] {file_path}\n"
            f"[bold]Target Endpoint:[/bold] POST /wallet/withdraw\n"
            f"[bold]Concurrent Barrier Workers:[/bold] {result['workers']}\n"
            f"[bold]Initial Wallet Balance:[/bold] ${result['initial_balance']}\n"
            f"[bold]Successful Withdrawals ($50 each):[/bold] "
            f"[bold red]{result['success_count']}[/bold red]\n"
            f"[bold]Final Resulting Balance:[/bold] "
            f"[bold red]${result['final_balance']}[/bold red]\n\n"
            f"[bold red]INVARIANT VIOLATION PROVEN:[/bold red]\n"
            f"Multiple concurrent withdrawals succeeded against a $50 balance due to an unlocked "
            f"Read-Modify-Write race condition (CG-001).\n"
            f"Expected max 1 successful withdrawal, but {result['success_count']} requests succeeded!"
        )
        console.print(
            Panel(
                proof_text,
                title="[bold red]❌ CONCURRENCY INVARIANT VIOLATED (RACE PROVEN)[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    safe_text = (
        f"[bold]Target File:[/bold] {file_path}\n"
        f"[bold]Target Endpoint:[/bold] POST /wallet/withdraw\n"
        f"[bold]Concurrent Barrier Workers:[/bold] {result['workers']}\n"
        f"[bold]Initial Wallet Balance:[/bold] ${result['initial_balance']}\n"
        f"[bold]Successful Withdrawals:[/bold] {result['success_count']}\n"
        f"[bold]Final Balance:[/bold] ${result['final_balance']}\n\n"
        f"[bold green]Row-level locking preserved the concurrency invariant under barrier stress.[/bold green]"
    )
    console.print(
        Panel(
            safe_text,
            title="[bold green]✔ CONCURRENCY INVARIANT HELD[/bold green]",
            border_style="green",
        )
    )
    raise typer.Exit(code=0)


@app.command()
def fix(
    file_path: Path = typer.Argument(
        ...,
        exists=True,
        help="Target Python file to auto-patch with concurrency fixes",
    ),
    write: bool = typer.Option(
        False,
        "--write",
        help="Write the patched code back to disk",
    ),
) -> None:
    """Auto-patch concurrency race conditions by appending .with_for_update() using LibCST."""
    source_code = file_path.read_text(encoding="utf-8")
    patched_code = apply_with_for_update_fix(source_code)

    if source_code == patched_code:
        console.print(
            Panel(
                f"[bold green]No concurrency fixes needed for {file_path}.[/bold green]",
                border_style="green",
            )
        )
        raise typer.Exit(code=0)

    diff = "".join(
        difflib.unified_diff(
            source_code.splitlines(keepends=True),
            patched_code.splitlines(keepends=True),
            fromfile=str(file_path),
            tofile=f"{file_path} (patched)",
        )
    )

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


if __name__ == "__main__":
    app()

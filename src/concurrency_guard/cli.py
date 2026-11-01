"""Command line interface for Concurrency Guard."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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


if __name__ == "__main__":
    app()

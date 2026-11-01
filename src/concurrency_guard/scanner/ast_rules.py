"""AST scanning rules for concurrency and idempotency vulnerabilities."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ASTFinding:
    """Represents a vulnerability finding discovered by AST analysis."""

    rule_id: str
    filename: str
    lineno: int
    function_name: str
    message: str
    suggested_fix_hint: str


def _walk_local_nodes(node: ast.AST) -> Iterator[ast.AST]:
    """Walk child nodes without descending into nested function definitions."""
    for child in ast.iter_child_nodes(node):
        yield child
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield from _walk_local_nodes(child)


def _is_matching_binop_mutation(stmt: ast.Assign) -> bool:
    """Check if an Assign mutates an attribute using that same attribute in a BinOp."""
    if not (stmt.targets and isinstance(stmt.targets[0], ast.Attribute)):
        return False

    target_attr = stmt.targets[0]
    target_unparsed = ast.unparse(target_attr)

    for child in ast.walk(stmt.value):
        if isinstance(child, ast.BinOp):
            for inner in ast.walk(child):
                if isinstance(inner, ast.Attribute) and ast.unparse(inner) == target_unparsed:
                    return True
    return False


class ConcurrencyASTVisitor(ast.NodeVisitor):
    """AST visitor detecting concurrency race conditions in async functions."""

    def __init__(self, filename: str = "<memory>") -> None:
        self.filename = filename
        self.findings: list[ASTFinding] = []

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Inspect async function definitions for Rule CG-001."""
        local_nodes = list(_walk_local_nodes(node))

        # Check for select(...) call
        select_calls: list[ast.Call] = []
        for n in local_nodes:
            if isinstance(n, ast.Call):
                func = n.func
                if (isinstance(func, ast.Name) and func.id == "select") or (
                    isinstance(func, ast.Attribute) and func.attr == "select"
                ):
                    select_calls.append(n)

        # Check for attribute mutation (AugAssign or Assign with BinOp referencing same attr)
        has_mutation = False
        for n in local_nodes:
            if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Attribute):
                has_mutation = True
                break
            if isinstance(n, ast.Assign) and _is_matching_binop_mutation(n):
                has_mutation = True
                break

        # Check for .commit()
        has_commit = any(
            isinstance(n, ast.Attribute) and n.attr == "commit" for n in local_nodes
        )

        # Check for .with_for_update()
        has_with_for_update = any(
            isinstance(n, ast.Attribute) and n.attr == "with_for_update" for n in local_nodes
        )

        # Rule CG-001: Unlocked Read-Modify-Write Race Condition
        if select_calls and has_mutation and has_commit and not has_with_for_update:
            first_select = select_calls[0]
            self.findings.append(
                ASTFinding(
                    rule_id="CG-001",
                    filename=self.filename,
                    lineno=first_select.lineno,
                    function_name=node.name,
                    message=(
                        "Unlocked Read-Modify-Write Race Condition: database state is read and "
                        "mutated without '.with_for_update()' lock before commit."
                    ),
                    suggested_fix_hint=(
                        "Add '.with_for_update()' to the select statement to acquire row locks "
                        "and prevent concurrent lost updates."
                    ),
                )
            )

        self.generic_visit(node)


def scan_source_code(source_code: str, filename: str = "<memory>") -> list[ASTFinding]:
    """Scan Python source code string for concurrency vulnerabilities."""
    tree = ast.parse(source_code, filename=filename)
    visitor = ConcurrencyASTVisitor(filename=filename)
    visitor.visit(tree)
    return visitor.findings


def scan_file(file_path: Path) -> list[ASTFinding]:
    """Scan a Python file for concurrency vulnerabilities."""
    source_code = file_path.read_text(encoding="utf-8")
    return scan_source_code(source_code, filename=str(file_path))

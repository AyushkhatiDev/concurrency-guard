"""AST scanning rules for concurrency and idempotency vulnerabilities."""

from __future__ import annotations

import ast
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "migrations",
    "alembic",
})


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


def _is_select_call(node: ast.AST) -> bool:
    """Check if node is a select(...) call."""
    if isinstance(node, ast.Call):
        func = node.func
        if (isinstance(func, ast.Name) and func.id == "select") or (
            isinstance(func, ast.Attribute) and func.attr == "select"
        ):
            return True
    return False


def _is_db_or_session(val: ast.AST) -> bool:
    """Check if AST value refers to a database or session object."""
    if isinstance(val, ast.Name):
        name = val.id.lower()
        return any(k in name for k in ("db", "session", "conn"))
    if isinstance(val, ast.Attribute):
        name = val.attr.lower()
        return any(k in name for k in ("db", "session", "conn"))
    return False


def _is_query_call(node: ast.AST) -> bool:
    """Check if node is a select(...) call or SQLAlchemy 2.0 scalar/scalars/get query."""
    if _is_select_call(node):
        return True
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("scalar", "scalars", "get")
        and _is_db_or_session(node.func.value)
    )


def _is_add_call(node: ast.AST) -> bool:
    """Check if node is a db.add(...) or session.add(...) call."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add":
        return _is_db_or_session(node.func.value)
    return False


def _is_commit_call(node: ast.AST) -> bool:
    """Check if node is a .commit() call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "commit"
    )


def _is_post_route(node: ast.AsyncFunctionDef) -> bool:
    """Check if function is decorated with @app.post or @router.post."""
    for dec in node.decorator_list:
        func = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(func, ast.Attribute) and func.attr == "post":
            return True
    return False


def _has_idempotency_param(node: ast.AsyncFunctionDef) -> bool:
    """Check if parameter list includes an idempotency_key parameter or header."""
    all_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
    for arg in all_args:
        name = arg.arg.lower()
        if "idempotency" in name:
            return True
        if arg.annotation and "idempotency" in ast.unparse(arg.annotation).lower():
            return True

    all_defaults = [d for d in node.args.defaults if d is not None] + [
        d for d in node.args.kw_defaults if d is not None
    ]
    for d in all_defaults:
        if "idempotency" in ast.unparse(d).lower():
            return True

    return False


def _find_loop_execute_calls(node: ast.AST, in_loop: bool = False) -> list[ast.Call]:
    """Find db/session execute, scalar, scalars, or get calls directly within loop bodies."""
    calls: list[ast.Call] = []
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        if (
            in_loop
            and isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr in ("execute", "scalar", "scalars", "get")
            and _is_db_or_session(child.func.value)
        ):
            calls.append(child)

        if isinstance(child, (ast.For, ast.AsyncFor)):
            for b in child.body:
                calls.extend(_find_loop_execute_calls(b, in_loop=True))
            for o in child.orelse:
                calls.extend(_find_loop_execute_calls(o, in_loop=True))
        else:
            calls.extend(_find_loop_execute_calls(child, in_loop=in_loop))
    return calls


def _catches_integrity_error(try_node: ast.Try) -> bool:
    """Check if Try block has an except handler catching IntegrityError."""
    for handler in try_node.handlers:
        if handler.type is None:
            continue
        types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        for t in types:
            if isinstance(t, ast.Name) and t.id == "IntegrityError":
                return True
            if isinstance(t, ast.Attribute) and t.attr == "IntegrityError":
                return True
    return False


def _is_commit_protected(node: ast.AsyncFunctionDef) -> bool:
    """Check if any commit call is wrapped in a try/except catching IntegrityError."""
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
            continue
        if isinstance(child, ast.Try) and _catches_integrity_error(child):
            for stmt in child.body:
                for sub in ast.walk(stmt):
                    if _is_commit_call(sub):
                        return True
    return False


def _is_celery_task(dec: ast.AST) -> bool:
    """Check if decorator is a Celery task decorator like @app.task, @celery.task, or @shared_task."""
    func = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(func, ast.Attribute) and func.attr == "task":
        return True
    return bool(isinstance(func, ast.Name) and func.id in ("shared_task", "task"))


def _has_celery_retry_kwarg(dec: ast.AST) -> bool:
    """Check if decorator has autoretry_for or max_retries keyword arguments."""
    if not isinstance(dec, ast.Call):
        return False
    for kw in dec.keywords:
        if kw.arg in ("autoretry_for", "max_retries"):
            return True
    return False


def _has_acks_late_true(dec: ast.AST) -> bool:
    """Check if decorator specifies acks_late=True."""
    if not isinstance(dec, ast.Call):
        return False
    for kw in dec.keywords:
        if kw.arg == "acks_late" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _has_mutation_or_side_effect(local_nodes: list[ast.AST]) -> bool:
    """Check if body contains .add(), .commit(), or .post() call."""
    for n in local_nodes:
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("add", "commit", "post")
        ):
            return True
    return False


def _has_idempotency_or_lock(local_nodes: list[ast.AST], docstring: str | None = None) -> bool:
    """Check if body checks an idempotency or deduplication lock."""
    for n in local_nodes:
        if isinstance(n, ast.Name):
            lower = n.id.lower()
            if any(k in lower for k in ("idempotency", "dedup", "lock")):
                return True
        elif isinstance(n, ast.Attribute):
            lower = n.attr.lower()
            if any(k in lower for k in ("idempotency", "dedup", "lock")):
                return True
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            if docstring and n.value == docstring:
                continue
            lower = n.value.lower()
            if any(k in lower for k in ("idempotency", "dedup")):
                return True
    return False


class ConcurrencyASTVisitor(ast.NodeVisitor):
    """AST visitor detecting concurrency race conditions and idempotency issues."""

    def __init__(self, filename: str = "<memory>") -> None:
        self.filename = filename
        self.findings: list[ASTFinding] = []

    def _check_cg_001(self, node: ast.AsyncFunctionDef, local_nodes: list[ast.AST]) -> None:
        """Rule CG-001: Unlocked Read-Modify-Write Race Condition."""
        query_calls = [n for n in local_nodes if isinstance(n, ast.Call) and _is_query_call(n)]

        has_mutation = False
        for n in local_nodes:
            if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Attribute):
                has_mutation = True
                break
            if isinstance(n, ast.Assign) and _is_matching_binop_mutation(n):
                has_mutation = True
                break

        has_commit = any(
            isinstance(n, ast.Attribute) and n.attr == "commit" for n in local_nodes
        )

        has_with_for_update = any(
            isinstance(n, ast.Attribute) and n.attr == "with_for_update" for n in local_nodes
        )

        if query_calls and has_mutation and has_commit and not has_with_for_update:
            first_query = query_calls[0]
            self.findings.append(
                ASTFinding(
                    rule_id="CG-001",
                    filename=self.filename,
                    lineno=first_query.lineno,
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

    def _check_cg_002(self, node: ast.AsyncFunctionDef, local_nodes: list[ast.AST]) -> None:
        """Rule CG-002: Missing Idempotency Guard on POST Routes."""
        if not _is_post_route(node):
            return

        has_db_mutation = any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("commit", "add")
            for n in local_nodes
        )

        if not has_db_mutation:
            return

        if not _has_idempotency_param(node):
            self.findings.append(
                ASTFinding(
                    rule_id="CG-002",
                    filename=self.filename,
                    lineno=node.lineno,
                    function_name=node.name,
                    message=(
                        "Missing Idempotency Guard: POST route executes database modification "
                        "without an 'Idempotency-Key' parameter."
                    ),
                    suggested_fix_hint=(
                        "Require an 'Idempotency-Key' header in FastAPI request parameters "
                        "to prevent duplicate submissions on network retries."
                    ),
                )
            )

    def _check_cg_003(self, node: ast.AsyncFunctionDef) -> None:
        """Rule CG-003: Async Loop N+1 Query Explode."""
        loop_execute_calls = _find_loop_execute_calls(node, in_loop=False)
        for call in loop_execute_calls:
            self.findings.append(
                ASTFinding(
                    rule_id="CG-003",
                    filename=self.filename,
                    lineno=call.lineno,
                    function_name=node.name,
                    message="Async Loop N+1 Query Explode: database query executed inside loop body.",
                    suggested_fix_hint=(
                        "Move the query outside the loop or use joinedload/selectinload "
                        "to fetch related data in a single batch query."
                    ),
                )
            )

    def _check_cg_004(self, node: ast.AsyncFunctionDef, local_nodes: list[ast.AST]) -> None:
        """Rule CG-004: Check-Then-Act Uniqueness Race."""
        query_calls = [n for n in local_nodes if isinstance(n, ast.Call) and _is_query_call(n)]
        add_calls = [n for n in local_nodes if isinstance(n, ast.Call) and _is_add_call(n)]
        has_commit = any(_is_commit_call(n) for n in local_nodes)

        if query_calls and add_calls and has_commit:
            first_query = query_calls[0]
            first_add = add_calls[0]
            if first_query.lineno <= first_add.lineno and not _is_commit_protected(node):
                self.findings.append(
                    ASTFinding(
                        rule_id="CG-004",
                        filename=self.filename,
                        lineno=first_query.lineno,
                        function_name=node.name,
                        message=(
                            "Check-Then-Act Uniqueness Race: select() existence check followed by "
                            "add() and commit() without catching IntegrityError."
                        ),
                        suggested_fix_hint=(
                            "Wrap database commit in a try/except block catching "
                            "sqlalchemy.exc.IntegrityError to handle concurrent unique constraint violations safely."
                        ),
                    )
                )

    def _check_cg_005(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        local_nodes: list[ast.AST],
    ) -> None:
        """Rule CG-005: Non-Idempotent Celery Retry Task."""
        matching_task_dec: ast.AST | None = None
        has_retry = False
        has_acks_late = False

        for dec in node.decorator_list:
            if _is_celery_task(dec):
                matching_task_dec = dec
                if _has_celery_retry_kwarg(dec):
                    has_retry = True
                if _has_acks_late_true(dec):
                    has_acks_late = True

        if not matching_task_dec or not has_retry:
            return

        docstring = ast.get_docstring(node)
        if has_acks_late or _has_idempotency_or_lock(local_nodes, docstring=docstring):
            return

        if _has_mutation_or_side_effect(local_nodes):
            self.findings.append(
                ASTFinding(
                    rule_id="CG-005",
                    filename=self.filename,
                    lineno=node.lineno,
                    function_name=node.name,
                    message=(
                        "Non-Idempotent Celery Retry Task: Celery task configured with retries "
                        "executes side effects without acks_late=True or idempotency deduplication lock."
                    ),
                    suggested_fix_hint=(
                        "Add 'acks_late=True' to the Celery task decorator and enforce an "
                        "idempotency lock before executing database commits or external POST calls on retry."
                    ),
                )
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect sync function definitions for rule CG-005."""
        local_nodes = list(_walk_local_nodes(node))
        self._check_cg_005(node, local_nodes)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Inspect async function definitions for rules CG-001, CG-002, CG-003, CG-004, and CG-005."""
        local_nodes = list(_walk_local_nodes(node))
        self._check_cg_001(node, local_nodes)
        self._check_cg_002(node, local_nodes)
        self._check_cg_003(node)
        self._check_cg_004(node, local_nodes)
        self._check_cg_005(node, local_nodes)
        self.generic_visit(node)


def scan_source_code(source_code: str, filename: str = "<memory>") -> list[ASTFinding]:
    """Scan Python source code string for concurrency vulnerabilities."""
    tree = ast.parse(source_code, filename=filename)
    visitor = ConcurrencyASTVisitor(filename=filename)
    visitor.visit(tree)
    return visitor.findings


def discover_python_files(path: Path) -> list[Path]:
    """Discover Python files in a directory or file, skipping hidden and excluded folders."""
    if not path.is_dir():
        return [path]

    py_files: list[Path] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in EXCLUDED_DIRS]
        for f in sorted(files):
            if f.endswith(".py"):
                py_files.append(Path(root) / f)
    return sorted(py_files)


def scan_file(file_path: Path) -> list[ASTFinding]:
    """Scan a Python file for concurrency vulnerabilities, skipping unparseable files."""
    try:
        source_code = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    try:
        return scan_source_code(source_code, filename=str(file_path))
    except SyntaxError:
        return []


def scan_directory(dir_path: Path) -> list[ASTFinding]:
    """Scan a directory recursively for concurrency vulnerabilities, skipping excluded directories."""
    findings: list[ASTFinding] = []
    for file_path in discover_python_files(dir_path):
        findings.extend(scan_file(file_path))
    return findings

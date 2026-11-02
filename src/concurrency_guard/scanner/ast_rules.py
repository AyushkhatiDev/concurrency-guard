"""AST scanning rules for concurrency and idempotency vulnerabilities."""

from __future__ import annotations

import ast
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import yaml  # type: ignore[import-untyped]

from concurrency_guard.scanner.call_graph import build_call_graph
from concurrency_guard.scanner.taint_tracker import (
    find_tainted_shared_state_mutations,
    find_tainted_shared_state_mutations_in_source,
)

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


@dataclass(frozen=True)
class CFGNode:
    """A deliberately small, inspectable control-flow graph node.

    The graph is not an executor: it provides the sequencing backbone used by
    semantic rules, including branches and loop back-edges.
    """

    lineno: int
    kind: str
    successors: tuple[int, ...]


def build_cfg(function: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> list[CFGNode]:
    """Build a lightweight intra-procedural CFG for a function body."""
    statements = [n for n in ast.walk(function) if isinstance(n, ast.stmt)]
    statements = sorted({id(n): n for n in statements}.values(), key=lambda n: (n.lineno, n.col_offset))
    result: list[CFGNode] = []
    for index, statement in enumerate(statements):
        next_line = statements[index + 1].lineno if index + 1 < len(statements) else -1
        successors: tuple[int, ...] = () if next_line == -1 else (next_line,)
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            successors = tuple(x for x in (next_line, statement.lineno) if x != -1)
        result.append(CFGNode(statement.lineno, type(statement).__name__, successors))
    return result


def _expr_name(node: ast.AST) -> str:
    """Return a stable dotted name for names, attributes, and calls."""
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _is_lock_expr(node: ast.AST) -> bool:
    name = _expr_name(node).lower()
    return "lock" in name or "semaphore" in name


def _lock_names(node: ast.AST) -> list[str]:
    """Find names held by with/async-with statements, preserving nesting order."""
    names: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, (ast.With, ast.AsyncWith)):
            for item in child.items:
                if _is_lock_expr(item.context_expr):
                    name = _expr_name(item.context_expr)
                    names.append(name or "<lock>")
    return names


def _has_lock_context(node: ast.AST) -> bool:
    return bool(_lock_names(node))


def _assignment_target_name(node: ast.AST) -> str:
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return ast.unparse(node)
    return ""


def _mutated_targets(node: ast.AST) -> set[str]:
    targets: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.AugAssign):
            targets.add(_assignment_target_name(child.target))
        elif isinstance(child, ast.Assign):
            for target in child.targets:
                targets.add(_assignment_target_name(target))
        elif (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr in {"append", "extend", "update", "pop", "remove", "setdefault", "clear"}
        ):
            targets.add(_assignment_target_name(child.func.value))
    return {target for target in targets if target}


def _is_concurrency_api(node: ast.AST) -> bool:
    return any(token in _expr_name(node).lower() for token in ("thread", "executor", "create_task", "gather", "process"))


def _is_file_write(call: ast.Call) -> bool:
    name = _expr_name(call.func)
    if name not in {"open", "aiofiles.open"} or len(call.args) < 2:
        return False
    mode = call.args[1]
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(x in mode.value for x in "wax+")


def _literal_path(call: ast.Call) -> Optional[str]:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    return None


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


def _has_idempotency_or_lock(local_nodes: list[ast.AST], docstring: Optional[str] = None) -> bool:
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


def _django_manager_call(call: ast.Call) -> tuple[bool, bool]:
    """Return whether a call fetches a Django model and has a row lock.

    The supported forms are ``Model.objects.get(...)`` and
    ``Model.objects.filter(...).first()``. The second value records a
    ``select_for_update()`` anywhere in the manager chain.
    """
    if not isinstance(call.func, ast.Attribute):
        return False, False
    method = call.func.attr
    manager: Optional[ast.AST] = None
    if method == "get":
        manager = call.func.value
    elif method == "first" and isinstance(call.func.value, ast.Call):
        filter_call = call.func.value
        if isinstance(filter_call.func, ast.Attribute) and filter_call.func.attr == "filter":
            manager = filter_call.func.value
    if manager is None:
        return False, False
    manager_name = _expr_name(manager)
    is_django_manager = manager_name.endswith(".objects") or ".objects." in manager_name
    has_row_lock = any(
        isinstance(child, ast.Attribute) and child.attr == "select_for_update"
        for child in ast.walk(call)
    )
    return is_django_manager, has_row_lock


def _target_root_name(node: ast.AST) -> str:
    """Return the local name at the root of an attribute/subscript target."""
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


class ConcurrencyASTVisitor(ast.NodeVisitor):
    """AST visitor detecting concurrency race conditions and idempotency issues."""

    def __init__(self, filename: str = "<memory>") -> None:
        self.filename = filename
        self.findings: list[ASTFinding] = []
        self.shared_names: set[str] = set()
        self.thread_targets: set[str] = set()
        self.lock_orders: list[tuple[str, str, int, str]] = []

    def visit_Module(self, node: ast.Module) -> None:
        """Collect module shared state and thread entry points before functions."""
        for statement in node.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if isinstance(value, (ast.List, ast.Dict, ast.Set)):
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    self.shared_names.update(_assignment_target_name(t) for t in targets)
        for call in (n for n in ast.walk(node) if isinstance(n, ast.Call) and _is_concurrency_api(n.func)):
            for keyword in call.keywords:
                if keyword.arg in {"target", "fn", "func"} and isinstance(keyword.value, ast.Name):
                    self.thread_targets.add(keyword.value.id)
            for arg in call.args:
                if isinstance(arg, ast.Name):
                    self.thread_targets.add(arg.id)
        self.generic_visit(node)

    def _add(self, rule_id: str, node: ast.AST, function: str, message: str, hint: str) -> None:
        self.findings.append(ASTFinding(rule_id, self.filename, getattr(node, "lineno", 0), function, message, hint))

    def _check_standard_library_rules(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Detect shared-memory and file races without framework/ORM assumptions."""
        locked = _has_lock_context(node)
        mutations = _mutated_targets(node)
        shared_mutations = [m for m in mutations if m.split("[")[0].split(".")[0] in self.shared_names]
        is_thread_target = node.name in self.thread_targets

        if isinstance(node, ast.AsyncFunctionDef) and shared_mutations and not locked:
            self._add(
                "CG-006", node, node.name,
                "Async shared-state mutation without an asyncio.Lock context manager.",
                "Create a shared asyncio.Lock and wrap the read/write section in 'async with lock:'.",
            )
        if (is_thread_target or any(_is_concurrency_api(n) for n in local_nodes)) and shared_mutations and not locked:
            self._add(
                "CG-007", node, node.name,
                "Threaded shared built-in mutation without a threading.Lock or threading.RLock.",
                "Protect the shared collection with 'with lock:' (or redesign around a Queue).",
            )

        # Semantic RMW: remember a value read from an attribute/subscript, then
        # identify its later assignment back. This catches arbitrary classes,
        # schemas, and in-memory objects rather than only ORM entities.
        reads: dict[str, str] = {}
        for statement in sorted((n for n in local_nodes if isinstance(n, ast.stmt)), key=lambda n: n.lineno):
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
                value = statement.value
                if isinstance(value, (ast.Attribute, ast.Subscript)):
                    reads[statement.targets[0].id] = ast.unparse(value)
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    target_name = _assignment_target_name(target)
                    value_names = {n.id for n in ast.walk(statement.value) if isinstance(n, ast.Name)}
                    if target_name in reads.values() and value_names.intersection(reads) and not locked:
                        self._add(
                            "CG-008", statement, node.name,
                            "Read-Modify-Write race: state is read, transformed, and written back without a lock.",
                            "Use the appropriate async/thread/process lock or an atomic update primitive around the full RMW sequence.",
                        )
                        break

        for call in (n for n in local_nodes if isinstance(n, ast.Call) and _is_file_write(n)):
            path = _literal_path(call)
            concurrent = isinstance(node, ast.AsyncFunctionDef) or is_thread_target or any(isinstance(n, (ast.For, ast.AsyncFor)) for n in local_nodes)
            if concurrent and not locked:
                self._add(
                    "CG-009", call, node.name,
                    "Concurrent file overwrite: write-mode open() may race on a shared path.",
                    "Use a file lock, unique per-task filenames, or serialize writes through one worker.",
                )
            if path and (path.startswith("/tmp/") or "tmp" in path.lower()):
                self._add(
                    "CG-010", call, node.name,
                    "Hard-coded temporary filename can collide between concurrent tasks.",
                    "Use tempfile.NamedTemporaryFile, TemporaryDirectory, or mkstemp instead.",
                )

        calls = [n for n in local_nodes if isinstance(n, ast.Call)]
        redis_gets = [n for n in calls if _expr_name(n.func).lower().endswith((".get", ".mget")) and "redis" in _expr_name(n.func).lower()]
        redis_sets = [n for n in calls if _expr_name(n.func).lower().endswith((".set", ".setex")) and "redis" in _expr_name(n.func).lower()]
        memcached_non_atomic = [n for n in calls if "memcache" in _expr_name(n.func).lower() and _expr_name(n.func).lower().endswith(".set")]
        if redis_gets and redis_sets and not locked and not any("setnx" in _expr_name(c.func).lower() or "lua" in _expr_name(c.func).lower() for c in calls):
            self._add("CG-011", redis_gets[0], node.name, "Redis check-then-act sequence is non-atomic.", "Use SET NX/EX, a Redis lock, WATCH/MULTI, or a Lua script.")
        if memcached_non_atomic and any(".get" in _expr_name(c.func).lower() for c in calls):
            self._add("CG-012", memcached_non_atomic[0], node.name, "Memcached get/set increment is non-atomic.", "Use Memcached incr/decr or a compare-and-swap workflow.")

        for with_node in (n for n in ast.walk(node) if isinstance(n, (ast.With, ast.AsyncWith))):
            outer = [_expr_name(item.context_expr) for item in with_node.items if _is_lock_expr(item.context_expr)]
            for nested in (n for n in ast.walk(with_node) if n is not with_node and isinstance(n, (ast.With, ast.AsyncWith))):
                inner = [_expr_name(item.context_expr) for item in nested.items if _is_lock_expr(item.context_expr)]
                for first in outer:
                    for second in inner:
                        self.lock_orders.append((first, second, with_node.lineno, node.name))

    def _check_deadlocks(self) -> None:
        reported: set[tuple[str, str]] = set()
        for first, second, line, function in self.lock_orders:
            for reverse_first, reverse_second, _, _ in self.lock_orders:
                pair = (min(first, second), max(first, second))
                if first == reverse_second and second == reverse_first and first != second and pair not in reported:
                    reported.add(pair)
                    self.findings.append(ASTFinding("CG-013", self.filename, line, function, f"Potential deterministic deadlock: locks '{first}' and '{second}' are acquired in reverse order.", "Adopt one global lock ordering, or replace nested locks with a single higher-level lock."))

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
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        local_nodes: list[ast.AST],
    ) -> None:
        """Rule CG-005: Non-Idempotent Celery Retry Task."""
        matching_task_dec: Optional[ast.AST] = None
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

    def _check_cg_016(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-016: Django object fetch/mutate/save without select_for_update()."""
        tracked_models: set[str] = set()
        unlocked_fetches: dict[str, ast.Call] = {}
        mutated: set[str] = set()

        statements = sorted((item for item in local_nodes if isinstance(item, ast.stmt)), key=lambda item: item.lineno)
        for statement in statements:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
                if isinstance(target, ast.Name):
                    if isinstance(statement.value, ast.Call):
                        is_fetch, has_lock = _django_manager_call(statement.value)
                        if is_fetch:
                            tracked_models.add(target.id)
                            if not has_lock:
                                unlocked_fetches[target.id] = statement.value
                    elif isinstance(statement.value, ast.Name) and statement.value.id in tracked_models:
                        # Preserve taint through aliases such as ``account = user``.
                        tracked_models.add(target.id)
                        if statement.value.id in unlocked_fetches:
                            unlocked_fetches[target.id] = unlocked_fetches[statement.value.id]
            elif isinstance(statement, ast.AugAssign) and _target_root_name(statement.target) in tracked_models:
                mutated.add(_target_root_name(statement.target))
            elif isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Attribute) and _target_root_name(target) in tracked_models:
                        mutated.add(_target_root_name(target))

            for call in (item for item in ast.walk(statement) if isinstance(item, ast.Call)):
                if isinstance(call.func, ast.Attribute) and call.func.attr == "save":
                    saved_name = _target_root_name(call.func.value)
                    fetch = unlocked_fetches.get(saved_name)
                    if fetch is not None and saved_name in mutated:
                        self._add(
                            "CG-016",
                            fetch,
                            node.name,
                            "Django Unlocked Read-Modify-Write: a model fetched through objects is mutated and saved without select_for_update().",
                            "Fetch the row with '.objects.select_for_update().get(...)' (or before filter().first()) inside transaction.atomic().",
                        )
                        return

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect sync function definitions for rule CG-005."""
        local_nodes = list(_walk_local_nodes(node))
        self._check_cg_005(node, local_nodes)
        self._check_cg_016(node, local_nodes)
        self._check_standard_library_rules(node, local_nodes)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Inspect async function definitions for rules CG-001, CG-002, CG-003, CG-004, and CG-005."""
        local_nodes = list(_walk_local_nodes(node))
        self._check_cg_001(node, local_nodes)
        self._check_cg_002(node, local_nodes)
        self._check_cg_003(node)
        self._check_cg_004(node, local_nodes)
        self._check_cg_005(node, local_nodes)
        self._check_cg_016(node, local_nodes)
        self._check_standard_library_rules(node, local_nodes)
        self.generic_visit(node)


def _custom_rule_findings(tree: ast.AST, filename: str, rules: list[dict[str, Any]]) -> list[ASTFinding]:
    """Evaluate compact YAML rules against functions without executing YAML content.

    Supported fields are ``id``/``rule_id``, ``function`` (called dotted name),
    ``modifies`` (target text), and ``without_context`` (required context text).
    A rule matches when all supplied positive predicates match and its context is
    absent. This intentionally small DSL is predictable and safe to extend.
    """
    findings: list[ASTFinding] = []
    for function in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        nodes = list(_walk_local_nodes(function))
        calls = {_expr_name(n.func) for n in nodes if isinstance(n, ast.Call)}
        modified = _mutated_targets(function)
        contexts = {_expr_name(item.context_expr) for n in ast.walk(function) if isinstance(n, (ast.With, ast.AsyncWith)) for item in n.items}
        for rule in rules:
            rule_id = str(rule.get("id", rule.get("rule_id", "CUSTOM")))
            wanted_function = rule.get("function") or rule.get("call")
            wanted_modify = rule.get("modifies") or rule.get("variable")
            missing_context = rule.get("without_context") or rule.get("without_lock")
            if wanted_function and not any(str(wanted_function) in call for call in calls):
                continue
            if wanted_modify and not any(str(wanted_modify) in target for target in modified):
                continue
            if missing_context and any(str(missing_context) in context for context in contexts):
                continue
            if not wanted_function and not wanted_modify:
                continue
            findings.append(ASTFinding(
                rule_id, filename, function.lineno, function.name,
                str(rule.get("message", f"Custom concurrency rule {rule_id} matched.")),
                str(rule.get("suggested_fix_hint", rule.get("fix", "Add the required synchronization guard."))),
            ))
    return list(dict.fromkeys(findings))


def load_yaml_rules(rule_file: Path) -> list[dict[str, Any]]:
    """Load and validate a YAML rule document (a list or ``rules:`` mapping)."""
    document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
    raw_rules = document.get("rules", []) if isinstance(document, dict) else document
    if not isinstance(raw_rules, list) or not all(isinstance(rule, dict) for rule in raw_rules):
        raise ValueError("Rule YAML must be a list of mappings or contain a 'rules:' list.")
    return raw_rules


def scan_source_code(
    source_code: str, filename: str = "<memory>", custom_rules: Optional[list[dict[str, Any]]] = None
) -> list[ASTFinding]:
    """Scan Python source code string for concurrency vulnerabilities."""
    tree = ast.parse(source_code, filename=filename)
    visitor = ConcurrencyASTVisitor(filename=filename)
    visitor.visit(tree)
    visitor._check_deadlocks()
    taint_findings = [
        ASTFinding(
            rule_id="CG-015",
            filename=finding.filename,
            lineno=finding.lineno,
            function_name=finding.function_name,
            message=(
                "Tainted Shared State Mutation: a local variable referencing shared state is "
                "mutated without concurrency controls."
            ),
            suggested_fix_hint=(
                "Protect the complete shared-state access with the appropriate lock or atomic "
                "operation before mutating the local reference."
            ),
        )
        for finding in find_tainted_shared_state_mutations_in_source(source_code, filename)
    ]
    return visitor.findings + taint_findings + (_custom_rule_findings(tree, filename, custom_rules) if custom_rules else [])


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


def scan_file(file_path: Path, custom_rules: Optional[list[dict[str, Any]]] = None) -> list[ASTFinding]:
    """Scan a Python file for concurrency vulnerabilities, skipping unparseable files."""
    try:
        source_code = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    try:
        return scan_source_code(source_code, filename=str(file_path), custom_rules=custom_rules)
    except SyntaxError:
        return []


def scan_directory(dir_path: Path, custom_rules: Optional[list[dict[str, Any]]] = None) -> list[ASTFinding]:
    """Scan a directory recursively, including cross-file call-chain analysis."""
    return scan_project(discover_python_files(dir_path), roots=[dir_path], custom_rules=custom_rules)


def scan_project(
    file_paths: list[Path], roots: Optional[list[Path]] = None, custom_rules: Optional[list[dict[str, Any]]] = None
) -> list[ASTFinding]:
    """Scan files and propagate shared-state hazards to transitive callers.

    CG-014 reports at a public caller when its cross-file call chain reaches a
    function that mutates module shared state. Graph construction reads source
    only; no scanned code is imported or executed.
    """
    findings: list[ASTFinding] = []
    for file_path in file_paths:
        findings.extend(scan_file(file_path, custom_rules=custom_rules))
    graph = build_call_graph(file_paths, roots=roots)
    taint_findings = find_tainted_shared_state_mutations(file_paths, graph)
    findings.extend(
        ASTFinding(
            rule_id="CG-015",
            filename=finding.filename,
            lineno=finding.lineno,
            function_name=finding.function_name,
            message=(
                "Tainted Shared State Mutation: a local variable referencing shared state is "
                "mutated without concurrency controls."
            ),
            suggested_fix_hint=(
                "Protect the complete shared-state access with the appropriate lock or atomic "
                "operation before mutating the local reference."
            ),
        )
        for finding in taint_findings
    )
    reported: set[tuple[str, str]] = set()
    for mutation in graph.shared_mutations:
        mutated = graph.functions[mutation]
        for caller_name in graph.callers_of(mutation):
            caller = graph.functions[caller_name]
            if caller.filename == mutated.filename:
                continue
            key = (caller_name, mutation)
            if key in reported:
                continue
            reported.add(key)
            findings.append(
                ASTFinding(
                    rule_id="CG-014",
                    filename=caller.filename,
                    lineno=caller.lineno,
                    function_name=caller.name,
                    message=(
                        f"Inter-procedural shared-state race: call chain reaches '{mutation}', "
                        "which mutates module shared state."
                    ),
                    suggested_fix_hint=(
                        "Propagate a lock or synchronization boundary through the call chain, "
                        "or make the shared-state operation atomic in the callee."
                    ),
                )
            )
    return list(dict.fromkeys(findings))

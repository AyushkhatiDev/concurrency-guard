"""AST scanning rules for concurrency and idempotency vulnerabilities."""

from __future__ import annotations

import ast
import os
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import yaml  # type: ignore[import-untyped]

from concurrency_guard.scanner.call_graph import build_call_graph
from concurrency_guard.scanner.suppression import SuppressionFilter
from concurrency_guard.scanner.taint_tracker import (
    find_tainted_shared_state_mutations,
    find_tainted_shared_state_mutations_in_source,
)

EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".venv",
    "venv",
    "env",
    ".env",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "migrations",
    "alembic",
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".eggs",
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
    confidence: str = "HIGH"
    end_lineno: Optional[int] = None


@dataclass
class _DjangoObjectFlow:
    """Provenance for one statically resolved Django model reference."""

    fetch: ast.AST
    row_locked: bool
    atomic_scopes: frozenset[int]
    mutated: bool = False
    reported: bool = False


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
    return any(k in name for k in ("lock", "semaphore", "mutex", "advisory_lock", "redis_lock", "redlock"))


_SCOPE_BOUNDARY_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _walk_local_nodes(node: ast.AST, include_self: bool = True) -> Iterator[ast.AST]:
    """Walk node and child nodes without descending into nested function definitions, classes, or lambdas."""
    if include_self:
        yield node
    for child in ast.iter_child_nodes(node):
        if not isinstance(child, _SCOPE_BOUNDARY_TYPES):
            yield from _walk_local_nodes(child, include_self=True)


def _get_lock_spans(node: ast.AST) -> list[tuple[int, int]]:
    """Return (start_line, end_line) spans for all with/async-with statements holding locks."""
    spans: list[tuple[int, int]] = []
    for child in _walk_local_nodes(node, include_self=isinstance(node, (ast.With, ast.AsyncWith))):
        if isinstance(child, (ast.With, ast.AsyncWith)):
            for item in child.items:
                if _is_lock_expr(item.context_expr):
                    start = child.lineno
                    end = getattr(child, "end_lineno", None)
                    if end is None:
                        end = max([getattr(c, "lineno", start) for c in _walk_local_nodes(child, include_self=True)] + [start])
                    spans.append((start, end))
    return spans


def _lock_names(node: ast.AST) -> list[str]:
    """Find names held by with/async-with statements, preserving nesting order."""
    names: list[str] = []
    for child in _walk_local_nodes(node, include_self=isinstance(node, (ast.With, ast.AsyncWith))):
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
    for child in _walk_local_nodes(node, include_self=True):
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
    name = _expr_name(node).lower()
    if any(
        token in name
        for token in (
            "threading.thread",
            "threadpoolexecutor",
            "processpoolexecutor",
            "asyncio.create_task",
            "asyncio.gather",
            "asyncio.taskgroup",
            "taskgroup",
            "multiprocessing.process",
            "backgroundtasks",
            "create_task_group",
        )
    ):
        return True
    parts = name.split(".")
    base = parts[-1]
    if base in {"thread", "create_task", "gather", "add_task", "start_soon"}:
        return True
    return bool(len(parts) > 1 and parts[-2] in {"threading", "multiprocessing", "asyncio", "anyio"})


def _extract_callable_name(node: ast.AST) -> Optional[str]:
    """Extract callable target name from Name, Attribute, or Call node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _extract_callable_name(node.func)
    return None


def _is_reentrant_lock(name: str) -> bool:
    """Check if lock expression name indicates a reentrant lock (e.g. RLock)."""
    low = name.lower()
    return "rlock" in low or "reentrant" in low


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
    """Check if node is a select(...) call or SQLAlchemy query."""
    if _is_select_call(node):
        return True
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr in ("scalar", "scalars", "get", "all", "first", "one", "one_or_none"):
        return _is_db_or_session(node.func.value)
    return bool(
        node.func.attr == "execute"
        and _is_db_or_session(node.func.value)
        and node.args
        and any(_is_select_call(arg) or any(_is_select_call(c) for c in ast.walk(arg)) for arg in node.args)
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


def _is_web_route(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
    """Check if function is decorated with a web route decorator."""
    for dec in node.decorator_list:
        func = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(func, ast.Attribute) and func.attr.lower() in {
            "get", "post", "put", "delete", "patch", "route", "api_route", "websocket"
        }:
            return True
    return False


def _has_celery_decorator(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
    """Check if function is decorated with a Celery task decorator."""
    return any(_is_celery_task(dec) for dec in node.decorator_list)


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
        if isinstance(child, _SCOPE_BOUNDARY_TYPES):
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
    for child in _walk_local_nodes(node):
        if isinstance(child, ast.Try) and _catches_integrity_error(child):
            for stmt in child.body:
                for sub in _walk_local_nodes(stmt):
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


def _django_manager_call(call: ast.AST) -> tuple[bool, bool]:
    """Return whether a call fetches a Django model and has a row lock.

    The supported forms are ``Model.objects.get(...)`` and
    ``Model.objects.filter(...).first()``, with optional ``select_for_update()``.
    """
    if isinstance(call, ast.Await) and isinstance(call.value, ast.Call):
        call = call.value
    if not isinstance(call, ast.Call):
        return False, False
    if not isinstance(call.func, ast.Attribute):
        return False, False
    method = call.func.attr
    if method not in {"get", "first", "last", "aget", "afirst", "alast"}:
        return False, False
    manager_name = _expr_name(call.func.value)
    chain = manager_name.split(".")
    is_model_chain = bool(chain and chain[0][:1].isupper() and len(chain) >= 2)
    is_django_manager = ".objects" in manager_name or manager_name == "objects" or is_model_chain
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
        self.aliases: dict[str, str] = {}
        self.context_stack: list[Union[ast.With, ast.AsyncWith]] = []
        self.reentrant_locks: set[str] = set()
        self.function_locks: dict[str, set[str]] = defaultdict(set)
        self.calls_under_lock: list[tuple[str, str, str, int]] = []

    def _is_reentrant(self, name: str) -> bool:
        low = name.lower()
        return "rlock" in low or "reentrant" in low or name in self.reentrant_locks or name.split(".")[-1] in self.reentrant_locks

    def resolve_alias(self, name: str) -> str:
        """Resolve an alias to its source name through the alias chain."""
        visited: set[str] = set()
        curr = name
        while curr in self.aliases and curr not in visited:
            visited.add(curr)
            curr = self.aliases[curr]
        return curr

    def set_alias(self, target: str, source: str) -> None:
        """Record an alias mapping from target to source."""
        resolved_source = self.resolve_alias(source)
        if target != resolved_source:
            self.aliases[target] = resolved_source

    def remove_alias(self, target: str) -> None:
        """Remove target from the active alias table."""
        self.aliases.pop(target, None)

    def is_in_async_lock(self) -> bool:
        """Return True if currently inside an active async with lock/semaphore block."""
        return any(
            isinstance(ctx, ast.AsyncWith) and any(_is_lock_expr(item.context_expr) for item in ctx.items)
            for ctx in self.context_stack
        )

    def is_in_sync_lock(self) -> bool:
        """Return True if currently inside an active with lock/semaphore block."""
        return any(
            isinstance(ctx, ast.With) and any(_is_lock_expr(item.context_expr) for item in ctx.items)
            for ctx in self.context_stack
        )

    def visit_With(self, node: ast.With) -> None:
        """Track entering and exiting sync with blocks."""
        self.context_stack.append(node)
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """Track entering and exiting async with blocks."""
        self.context_stack.append(node)
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments, aliases, and reentrant locks."""
        for target in node.targets:
            val_name = _expr_name(node.value).lower()
            if "rlock" in val_name or "reentrant" in val_name:
                tname = _expr_name(target)
                if tname:
                    self.reentrant_locks.add(tname)
            if isinstance(target, ast.Name):
                if isinstance(node.value, ast.Name):
                    self.set_alias(target.id, node.value.id)
                else:
                    self.remove_alias(target.id)
            elif (
                isinstance(target, (ast.Tuple, ast.List))
                and isinstance(node.value, (ast.Tuple, ast.List))
                and len(target.elts) == len(node.value.elts)
            ):
                for t_elt, v_elt in zip(target.elts, node.value.elts):
                    if isinstance(t_elt, ast.Name):
                        if isinstance(v_elt, ast.Name):
                            self.set_alias(t_elt.id, v_elt.id)
                        else:
                            self.remove_alias(t_elt.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Track annotated variable assignments, aliases, and reentrant locks."""
        if node.value is not None:
            val_name = _expr_name(node.value).lower()
            if "rlock" in val_name or "reentrant" in val_name:
                tname = _expr_name(node.target)
                if tname:
                    self.reentrant_locks.add(tname)
        if isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Name):
                self.set_alias(node.target.id, node.value.id)
            else:
                self.remove_alias(node.target.id)
        self.generic_visit(node)

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
                if keyword.arg in {"target", "fn", "func"}:
                    target = _extract_callable_name(keyword.value)
                    if target:
                        self.thread_targets.add(target)
            func_name = _expr_name(call.func).lower()
            if any(func_name.endswith(method) for method in (".submit", ".apply_async", ".apply", "create_task", "add_task", "start_soon")) or func_name in {"submit", "apply_async", "apply", "create_task", "add_task", "start_soon"}:
                if call.args:
                    target = _extract_callable_name(call.args[0])
                    if target:
                        self.thread_targets.add(target)
            elif "thread" in func_name and len(call.args) >= 2:
                target = _extract_callable_name(call.args[1])
                if target:
                    self.thread_targets.add(target)
        self.generic_visit(node)

    def _add(
        self,
        rule_id: str,
        node: ast.AST,
        function: str,
        message: str,
        hint: str,
        confidence: str = "HIGH",
    ) -> None:
        self.findings.append(
            ASTFinding(
                rule_id,
                self.filename,
                getattr(node, "lineno", 0),
                function,
                message,
                hint,
                confidence,
                end_lineno=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
            )
        )

    def _check_standard_library_rules(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Detect shared-memory and file races without framework/ORM assumptions."""
        locked = _has_lock_context(node)
        is_thread_target = node.name in self.thread_targets

        unlocked_async_mutations: list[tuple[str, ast.AST]] = []
        unlocked_sync_mutations: list[tuple[str, ast.AST]] = []

        def inspect_statements(
            stmts: list[ast.stmt], in_async_lock: bool, in_sync_lock: bool, epoch: int = 0,
            reads: Optional[dict[str, int]] = None,
        ) -> None:
            """Visit executable statements while modelling asyncio suspension epochs.

            A coroutine cannot be interleaved with another coroutine until it reaches
            an await/async-for/async-with boundary.  Consequently a bare mutation of
            a module collection is not itself a CG-006 race; it becomes one only
            when its read/modify/write window crosses an epoch.
            """
            reads = {} if reads is None else reads
            for stmt in stmts:
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Await):
                    epoch += 1
                    continue
                if isinstance(stmt, (ast.AsyncFor, ast.AsyncWith)):
                    epoch += 1
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and isinstance(stmt.value, ast.Name):
                            self.set_alias(target.id, stmt.value.id)
                        elif isinstance(target, ast.Name):
                            self.remove_alias(target.id)
                elif isinstance(stmt, ast.AnnAssign):
                    if isinstance(stmt.target, ast.Name) and isinstance(stmt.value, ast.Name):
                        self.set_alias(stmt.target.id, stmt.value.id)
                    elif isinstance(stmt.target, ast.Name):
                        self.remove_alias(stmt.target.id)

                if isinstance(stmt, ast.AsyncWith):
                    has_lock = any(_is_lock_expr(item.context_expr) for item in stmt.items)
                    inspect_statements(stmt.body, in_async_lock or has_lock, in_sync_lock, epoch, dict(reads))
                elif isinstance(stmt, ast.With):
                    has_lock = any(_is_lock_expr(item.context_expr) for item in stmt.items)
                    inspect_statements(stmt.body, in_async_lock, in_sync_lock or has_lock, epoch, dict(reads))
                elif isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                    inspect_statements(stmt.body, in_async_lock, in_sync_lock, epoch, dict(reads))
                    inspect_statements(stmt.orelse, in_async_lock, in_sync_lock, epoch, dict(reads))
                elif isinstance(stmt, ast.Try):
                    inspect_statements(stmt.body, in_async_lock, in_sync_lock, epoch, dict(reads))
                    inspect_statements(stmt.orelse, in_async_lock, in_sync_lock, epoch, dict(reads))
                    inspect_statements(stmt.finalbody, in_async_lock, in_sync_lock, epoch, dict(reads))
                    for handler in stmt.handlers:
                        inspect_statements(handler.body, in_async_lock, in_sync_lock, epoch, dict(reads))
                elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                else:
                    read_expression: Optional[ast.AST] = None
                    if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                        read_expression = stmt.value
                    for child in ast.walk(read_expression) if read_expression is not None else ():
                        if isinstance(child, ast.Subscript):
                            root = _target_root_name(child)
                            if root in self.shared_names or self.resolve_alias(root) in self.shared_names:
                                reads.setdefault(root, epoch)
                    if (
                        isinstance(stmt, ast.Assign)
                        and all(isinstance(t, ast.Name) for t in stmt.targets)
                        and all(t.id not in self.shared_names for t in stmt.targets if isinstance(t, ast.Name))
                    ):
                        continue
                    mutations = _mutated_targets(stmt)
                    for m in mutations:
                        root = m.split("[")[0].split(".")[0]
                        resolved = self.resolve_alias(root)
                        if root in self.shared_names or resolved in self.shared_names:
                            # A direct subscription read in an earlier epoch is a
                            # real cooperative RMW window.  Synchronous updates in
                            # one epoch are atomic with respect to asyncio tasks.
                            source_epoch = reads.get(root, reads.get(resolved))
                            # A blind write remains a potentially conflicting
                            # publication; a read/modify/write sequence is only
                            # unsafe when its read predates a suspension.
                            if not in_async_lock and (source_epoch is None or source_epoch < epoch):
                                unlocked_async_mutations.append((m, stmt))
                            if not in_sync_lock:
                                unlocked_sync_mutations.append((m, stmt))


        inspect_statements(node.body, in_async_lock=False, in_sync_lock=False)

        if isinstance(node, ast.AsyncFunctionDef) and unlocked_async_mutations:
            self._add(
                "CG-006", node, node.name,
                "Async shared-state mutation without an asyncio.Lock context manager.",
                "Create a shared asyncio.Lock and wrap the read/write section in 'async with lock:'.",
            )
        if (is_thread_target or any(_is_concurrency_api(n) for n in local_nodes)) and unlocked_sync_mutations:
            self._add(
                "CG-007", node, node.name,
                "Threaded shared built-in mutation without a threading.Lock or threading.RLock.",
                "Protect the shared collection with 'with lock:' (or redesign around a Queue).",
            )

        # Semantic RMW: remember a value read from an attribute/subscript, then
        # identify its later assignment back. This catches arbitrary classes,
        # schemas, and in-memory objects rather than only ORM entities.
        is_web_route = _is_web_route(node)
        is_celery = _has_celery_decorator(node)
        is_async = isinstance(node, ast.AsyncFunctionDef)
        is_concurrent_func = is_thread_target or is_web_route or is_celery or is_async

        rmw_reads: dict[str, tuple[str, int]] = {}
        for statement in sorted((n for n in local_nodes if isinstance(n, ast.stmt)), key=lambda n: getattr(n, "lineno", 0)):
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
                value = statement.value
                if isinstance(value, (ast.Attribute, ast.Subscript)):
                    rmw_reads[statement.targets[0].id] = (ast.unparse(value), getattr(statement, "lineno", 0))
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    target_name = _assignment_target_name(target)
                    value_names = {n.id for n in ast.walk(statement.value) if isinstance(n, ast.Name)}
                    matching_vars = [var for var in value_names if var in rmw_reads and rmw_reads[var][0] == target_name]
                    if matching_vars and not locked and is_concurrent_func:
                        read_var = matching_vars[0]
                        _read_expr, read_lineno = rmw_reads[read_var]
                        write_lineno = getattr(statement, "lineno", 0)

                        # If async coroutine without thread/web/celery concurrency, it is only a race
                        # if there is an intervening await suspension point between read and write.
                        if is_async and not (is_thread_target or is_web_route or is_celery):
                            has_intervening_await = any(
                                isinstance(n, (ast.Await, ast.AsyncFor, ast.AsyncWith))
                                and read_lineno <= getattr(n, "lineno", 0) <= write_lineno
                                for n in local_nodes
                            )
                            if not has_intervening_await:
                                continue

                        self._add(
                            "CG-008", statement, node.name,
                            "Read-Modify-Write race: state is read, transformed, and written back without a lock.",
                            "Use the appropriate async/thread/process lock or an atomic update primitive around the full RMW sequence.",
                            confidence="MEDIUM",
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
                    confidence="MEDIUM",
                )

        calls = [n for n in local_nodes if isinstance(n, ast.Call)]
        redis_gets = [n for n in calls if _expr_name(n.func).lower().endswith((".get", ".mget")) and "redis" in _expr_name(n.func).lower()]
        redis_sets = [n for n in calls if _expr_name(n.func).lower().endswith((".set", ".setex")) and "redis" in _expr_name(n.func).lower()]
        memcached_non_atomic = [n for n in calls if "memcache" in _expr_name(n.func).lower() and _expr_name(n.func).lower().endswith(".set")]
        if redis_gets and redis_sets and not locked and not any("setnx" in _expr_name(c.func).lower() or "lua" in _expr_name(c.func).lower() for c in calls):
            self._add("CG-011", redis_gets[0], node.name, "Redis check-then-act sequence is non-atomic.", "Use SET NX/EX, a Redis lock, WATCH/MULTI, or a Lua script.")
        if memcached_non_atomic and any(".get" in _expr_name(c.func).lower() for c in calls):
            self._add("CG-012", memcached_non_atomic[0], node.name, "Memcached get/set increment is non-atomic.", "Use Memcached incr/decr or a compare-and-swap workflow.")

        for with_node in (n for n in _walk_local_nodes(node) if isinstance(n, (ast.With, ast.AsyncWith))):
            outer = [_expr_name(item.context_expr) for item in with_node.items if _is_lock_expr(item.context_expr)]
            for lname in outer:
                if lname:
                    self.function_locks[node.name].add(lname)
            for call_child in (n for n in _walk_local_nodes(with_node) if isinstance(n, ast.Call)):
                callee_expr = _expr_name(call_child.func)
                callee_base = callee_expr.split(".")[-1]
                for olock in outer:
                    if olock:
                        self.calls_under_lock.append((node.name, olock, callee_base, with_node.lineno))
                        if callee_expr != callee_base:
                            self.calls_under_lock.append((node.name, olock, callee_expr, with_node.lineno))

            if len(outer) > 1:
                seen_locks: set[str] = set()
                for l in outer:
                    if l in seen_locks and not self._is_reentrant(l):
                        self._add(
                            "CG-013", with_node, node.name,
                            f"Non-reentrant self-deadlock: lock '{l}' is acquired multiple times in the same statement.",
                            f"Use threading.RLock or remove duplicate acquisition of '{l}'.",
                        )
                    seen_locks.add(l)

            for nested in (n for n in _walk_local_nodes(with_node) if n is not with_node and isinstance(n, (ast.With, ast.AsyncWith))):
                inner = [_expr_name(item.context_expr) for item in nested.items if _is_lock_expr(item.context_expr)]
                for first in outer:
                    for second in inner:
                        if first == second:
                            if not self._is_reentrant(first):
                                self._add(
                                    "CG-013", nested, node.name,
                                    f"Non-reentrant self-deadlock: lock '{first}' is acquired while already held.",
                                    f"Use threading.RLock instead of non-reentrant locks, or avoid re-acquiring '{first}'.",
                                )
                        else:
                            self.lock_orders.append((first, second, with_node.lineno, node.name))

    def _check_deadlocks(self) -> None:
        reported: set[tuple[str, str]] = set()
        for first, second, line, function in self.lock_orders:
            for reverse_first, reverse_second, _, _ in self.lock_orders:
                pair = (min(first, second), max(first, second))
                if first == reverse_second and second == reverse_first and first != second and pair not in reported:
                    reported.add(pair)
                    self.findings.append(ASTFinding("CG-013", self.filename, line, function, f"Potential deterministic deadlock: locks '{first}' and '{second}' are acquired in reverse order.", "Adopt one global lock ordering, or replace nested locks with a single higher-level lock."))

        # Inter-procedural non-reentrant self-deadlock
        inter_reported: set[tuple[str, str, str]] = set()
        for caller, lock, callee, lineno in self.calls_under_lock:
            callee_locks = self.function_locks.get(callee, set())
            if not callee_locks:
                base = callee.split(".")[-1]
                callee_locks = self.function_locks.get(base, set())
            if lock in callee_locks and not self._is_reentrant(lock):
                key = (caller, callee, lock)
                if key not in inter_reported:
                    inter_reported.add(key)
                    self.findings.append(
                        ASTFinding(
                            rule_id="CG-013",
                            filename=self.filename,
                            lineno=lineno,
                            function_name=caller,
                            message=(
                                f"Potential inter-procedural self-deadlock: '{caller}' acquires non-reentrant lock "
                                f"'{lock}' and calls '{callee}', which re-acquires the same lock."
                            ),
                            suggested_fix_hint=(
                                f"Use threading.RLock instead of non-reentrant lock '{lock}', "
                                f"or refactor '{callee}' to accept an already-locked context."
                            ),
                        )
                    )

    def _check_cg_001(self, node: ast.AsyncFunctionDef, local_nodes: list[ast.AST]) -> None:
        """Rule CG-001: Unlocked Read-Modify-Write Race Condition."""
        # 1. Fast check: must have a commit or flush call
        has_commit = any(
            _is_commit_call(n)
            or (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("commit", "flush")
            )
            for n in local_nodes
        )
        if not has_commit:
            return

        # 2. Collect lock spans: statements inside locks are safe
        lock_spans = _get_lock_spans(node)

        def is_locked_line(lineno: int) -> bool:
            return any(s <= lineno <= e for s, e in lock_spans)

        # 3. Build symbol def-use maps for queries and entity variables
        # Maps name -> (q_node, q_line, q_end_line, has_db_lock)
        queries: dict[str, tuple[ast.AST, int, int, bool]] = {}
        result_proxies: dict[str, tuple[ast.AST, int, int, bool]] = {}
        entity_sources: dict[str, tuple[ast.AST, int, int, bool]] = {}

        def _has_query_lock(expr: ast.AST) -> bool:
            return any(
                isinstance(c, ast.Attribute) and c.attr in ("with_for_update", "select_for_update")
                for c in ast.walk(expr)
            )

        def _extract_names(target: ast.AST) -> list[str]:
            if isinstance(target, ast.Name):
                return [target.id]
            if isinstance(target, ast.Starred):
                return _extract_names(target.value)
            if isinstance(target, (ast.Tuple, ast.List)):
                res: list[str] = []
                for elt in target.elts:
                    res.extend(_extract_names(elt))
                return res
            return []

        def _extract_query_execute(call_node: ast.AST) -> Optional[ast.Call]:
            """Unwind result proxy method chain (.scalars().all(), .scalar_one(), .first(), etc.) to the underlying db.execute() call."""
            curr = call_node
            while isinstance(curr, ast.Call) and isinstance(curr.func, ast.Attribute):
                if curr.func.attr == "execute" and _is_db_or_session(curr.func.value):
                    return curr
                if curr.func.attr in ("scalar", "scalars", "scalar_one", "scalar_one_or_none", "first", "one", "all"):
                    inner = curr.func.value
                    curr = inner.value if isinstance(inner, ast.Await) else inner
                else:
                    break
            return None

        assignment_pairs: list[tuple[list[Any], ast.AST, int, int]] = []
        for n in local_nodes:
            lineno = getattr(n, "lineno", 0)
            end_lineno = getattr(n, "end_lineno", lineno)
            if isinstance(n, ast.Assign):
                assignment_pairs.append((list(n.targets), n.value, lineno, end_lineno))
            elif isinstance(n, (ast.AnnAssign, ast.NamedExpr)) and n.value is not None:
                assignment_pairs.append(([n.target], n.value, lineno, end_lineno))

        assignment_pairs.sort(key=lambda x: x[2])

        for targets, val, stmt_lineno, stmt_end_lineno in assignment_pairs:
            if val is None:
                continue

            unwrapped = val.value if isinstance(val, ast.Await) else val

            # Check A: Assignment of a query, e.g. stmt = select(...)
            if any(_is_select_call(c) for c in ast.walk(unwrapped)):
                select_call = next(c for c in ast.walk(unwrapped) if _is_select_call(c))
                has_db_lock = _has_query_lock(unwrapped)
                sel_line = getattr(select_call, "lineno", stmt_lineno)
                sel_end = max(getattr(select_call, "end_lineno", sel_line), stmt_end_lineno)
                for t in targets:
                    for name in _extract_names(t):
                        queries[name] = (select_call, sel_line, sel_end, has_db_lock)

            # Check B: Database fetch calls: db.scalar(...), db.scalars(...), db.get(...), db.execute(...)
            if isinstance(unwrapped, ast.Call) and isinstance(unwrapped.func, ast.Attribute):
                attr = unwrapped.func.attr
                is_db = _is_db_or_session(unwrapped.func.value)

                if is_db and attr in ("scalar", "scalars"):
                    q_node: ast.AST = unwrapped
                    q_line = stmt_lineno
                    q_end_line = max(getattr(unwrapped, "end_lineno", stmt_lineno), stmt_end_lineno)
                    q_db_locked = False

                    if unwrapped.args:
                        arg0 = unwrapped.args[0]
                        if isinstance(arg0, ast.Name) and arg0.id in queries:
                            q_node, q_line, q_end_line, q_db_locked = queries[arg0.id]
                            q_end_line = max(q_end_line, stmt_end_lineno)
                        elif any(_is_select_call(c) for c in ast.walk(arg0)):
                            sel = next(c for c in ast.walk(arg0) if _is_select_call(c))
                            q_node = sel
                            q_line = getattr(sel, "lineno", stmt_lineno)
                            q_end_line = max(getattr(sel, "end_lineno", q_line), stmt_end_lineno)
                            q_db_locked = _has_query_lock(arg0)

                    for t in targets:
                        for name in _extract_names(t):
                            entity_sources[name] = (q_node, q_line, q_end_line, q_db_locked)

                elif is_db and attr in ("get", "first", "one", "one_or_none"):
                    q_db_locked = _has_query_lock(unwrapped)
                    q_end = max(getattr(unwrapped, "end_lineno", stmt_lineno), stmt_end_lineno)
                    for t in targets:
                        for name in _extract_names(t):
                            entity_sources[name] = (unwrapped, stmt_lineno, q_end, q_db_locked)

                elif is_db and attr == "execute":
                    q_node = unwrapped
                    q_line = stmt_lineno
                    q_end_line = max(getattr(unwrapped, "end_lineno", stmt_lineno), stmt_end_lineno)
                    q_db_locked = False

                    if unwrapped.args:
                        arg0 = unwrapped.args[0]
                        if isinstance(arg0, ast.Name) and arg0.id in queries:
                            q_node, q_line, q_end_line, q_db_locked = queries[arg0.id]
                            q_end_line = max(q_end_line, stmt_end_lineno)
                        elif any(_is_select_call(c) for c in ast.walk(arg0)):
                            sel = next(c for c in ast.walk(arg0) if _is_select_call(c))
                            q_node = sel
                            q_line = getattr(sel, "lineno", stmt_lineno)
                            q_end_line = max(getattr(sel, "end_lineno", q_line), stmt_end_lineno)
                            q_db_locked = _has_query_lock(arg0)

                    for t in targets:
                        for name in _extract_names(t):
                            result_proxies[name] = (q_node, q_line, q_end_line, q_db_locked)

                elif attr in ("scalar", "scalars", "scalar_one", "scalar_one_or_none", "first", "one", "all"):
                    root_name = _target_root_name(unwrapped.func.value)
                    if root_name in result_proxies:
                        q_node, q_line, q_end_line, q_db_locked = result_proxies[root_name]
                        q_end_line = max(q_end_line, stmt_end_lineno)
                        for t in targets:
                            for name in _extract_names(t):
                                entity_sources[name] = (q_node, q_line, q_end_line, q_db_locked)

            # Check C: Chained execute, e.g. user = (await session.execute(stmt)).scalar_one() or .scalars().all()
            exec_call = _extract_query_execute(unwrapped)
            if exec_call is not None and exec_call.args:
                arg0 = exec_call.args[0]
                if isinstance(arg0, ast.Name) and arg0.id in queries:
                    q_node, q_line, q_end_line, q_db_locked = queries[arg0.id]
                    q_end_line = max(q_end_line, stmt_end_lineno)
                elif any(_is_select_call(c) for c in ast.walk(arg0)):
                    sel = next(c for c in ast.walk(arg0) if _is_select_call(c))
                    q_node = sel
                    q_line = getattr(sel, "lineno", stmt_lineno)
                    q_end_line = max(getattr(sel, "end_lineno", q_line), stmt_end_lineno)
                    q_db_locked = _has_query_lock(arg0)
                else:
                    q_node = exec_call
                    q_line = stmt_lineno
                    q_end_line = stmt_end_lineno
                    q_db_locked = False
                for t in targets:
                    for name in _extract_names(t):
                        entity_sources[name] = (q_node, q_line, q_end_line, q_db_locked)

            # Check D: Aliasing, e.g. u = user
            if isinstance(unwrapped, ast.Name) and unwrapped.id in entity_sources:
                for t in targets:
                    for name in _extract_names(t):
                        entity_sources[name] = entity_sources[unwrapped.id]

        if not entity_sources:
            return

        # 4. Strict Def-Use Verification: detect in-memory attribute mutations of fetched entities
        # Each entry is (root_var, q_line, q_end_line)
        reported_entities: set[tuple[str, int, int]] = set()

        for stmt in local_nodes:
            stmt_line = getattr(stmt, "lineno", 0)
            if is_locked_line(stmt_line):
                continue

            # Case A: AugAssign, e.g. user.balance -= amount
            if isinstance(stmt, ast.AugAssign):
                root = _target_root_name(stmt.target)
                if root in entity_sources:
                    _, q_line, q_end_line, q_db_locked = entity_sources[root]
                    if not q_db_locked:
                        reported_entities.add((root, q_line, q_end_line))

            # Case B: Assign, e.g. user.balance = user.balance - amount or user.status = "active"
            elif isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, (ast.Attribute, ast.Subscript)):
                        root = _target_root_name(target)
                        if root in entity_sources:
                            is_atomic_f = any(
                                isinstance(c, ast.Call)
                                and (
                                    (isinstance(c.func, ast.Name) and c.func.id == "F")
                                    or (isinstance(c.func, ast.Attribute) and c.func.attr == "F")
                                )
                                for c in ast.walk(stmt.value)
                            )
                            if not is_atomic_f:
                                _, q_line, q_end_line, q_db_locked = entity_sources[root]
                                if not q_db_locked:
                                    reported_entities.add((root, q_line, q_end_line))

            # Case C: Mutating method calls, e.g. user.tags.append(...)
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if isinstance(call.func, ast.Attribute) and call.func.attr in {
                    "append", "extend", "update", "pop", "remove", "setdefault", "clear", "add"
                }:
                    root = _target_root_name(call.func.value)
                    if root in entity_sources:
                        _, q_line, q_end_line, q_db_locked = entity_sources[root]
                        if not q_db_locked:
                            reported_entities.add((root, q_line, q_end_line))

        # 5. Emit findings with HIGH confidence
        reported_lines: set[int] = set()
        for _, q_line, q_end_line in sorted(reported_entities, key=lambda x: x[1]):
            if q_line not in reported_lines:
                reported_lines.add(q_line)
                self.findings.append(
                    ASTFinding(
                        rule_id="CG-001",
                        filename=self.filename,
                        lineno=q_line,
                        function_name=node.name,
                        message=(
                            "Unlocked Read-Modify-Write Race Condition: database state is read and "
                            "mutated without '.with_for_update()' lock before commit."
                        ),
                        suggested_fix_hint=(
                            "Add '.with_for_update()' to the select statement to acquire row locks "
                            "and prevent concurrent lost updates."
                        ),
                        confidence="HIGH",
                        end_lineno=q_end_line,
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
                    end_lineno=getattr(node, "end_lineno", node.lineno),
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
                    end_lineno=getattr(call, "end_lineno", call.lineno),
                )
            )

    def _check_cg_004(self, node: ast.AsyncFunctionDef, local_nodes: list[ast.AST]) -> None:
        """Rule CG-004: Check-Then-Act Uniqueness Race."""
        query_calls = [n for n in local_nodes if isinstance(n, ast.Call) and _is_query_call(n)]
        add_calls = [n for n in local_nodes if isinstance(n, ast.Call) and _is_add_call(n)]
        commit_calls = [n for n in local_nodes if isinstance(n, ast.Call) and _is_commit_call(n)]

        if query_calls and add_calls and commit_calls:
            first_query = query_calls[0]
            first_add = add_calls[0]
            last_commit = commit_calls[-1]

            if first_query.lineno <= first_add.lineno and not _is_commit_protected(node):
                lock_spans = _get_lock_spans(node)
                is_safely_locked = any(
                    s <= first_query.lineno and last_commit.lineno <= e
                    for s, e in lock_spans
                )

                if not is_safely_locked:
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
                            confidence="HIGH",
                            end_lineno=getattr(first_query, "end_lineno", first_query.lineno),
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
                    end_lineno=getattr(node, "end_lineno", node.lineno),
                )
            )

    def _check_cg_016(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-016: prove an unsafe Django fetch/mutate/save path.

        Only straight-line flow within one lexical control-flow path is merged.
        This deliberately avoids inventing provenance through conditionals, loops,
        dynamic dispatch, or a transaction boundary that has already ended.
        """
        def is_atomic_context(expression: ast.AST) -> bool:
            expr_name = _expr_name(expression.func) if isinstance(expression, ast.Call) else _expr_name(expression)
            return expr_name in {
                "atomic", "transaction.atomic", "django.db.transaction.atomic",
            }

        def clone(flows: dict[str, _DjangoObjectFlow]) -> dict[str, _DjangoObjectFlow]:
            copies: dict[int, _DjangoObjectFlow] = {}
            for flow in flows.values():
                copies.setdefault(id(flow), _DjangoObjectFlow(
                    fetch=flow.fetch,
                    row_locked=flow.row_locked,
                    atomic_scopes=flow.atomic_scopes,
                    mutated=flow.mutated,
                    reported=flow.reported,
                ))
            return {name: copies[id(flow)] for name, flow in flows.items()}

        def calls(statement: ast.AST) -> Iterator[ast.Call]:
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    continue
                if isinstance(child, ast.Call):
                    yield child
                yield from calls(child)

        def protected(flow: _DjangoObjectFlow, active_scopes: tuple[int, ...]) -> bool:
            return flow.row_locked and bool(flow.atomic_scopes.intersection(active_scopes))

        def analyze_statement(
            statement: ast.stmt, active_scopes: tuple[int, ...], flows: dict[str, _DjangoObjectFlow]
        ) -> bool:
            if isinstance(statement, ast.Assign):
                target_names = [t.id for t in statement.targets if isinstance(t, ast.Name)]
                if target_names:
                    if isinstance(statement.value, (ast.Call, ast.Await)):
                        is_fetch, has_lock = _django_manager_call(statement.value)
                        for target in target_names:
                            if is_fetch:
                                flows[target] = _DjangoObjectFlow(
                                    fetch=statement.value,
                                    row_locked=has_lock,
                                    atomic_scopes=frozenset(active_scopes),
                                )
                                self.remove_alias(target)
                            else:
                                flows.pop(target, None)
                                self.remove_alias(target)
                    elif isinstance(statement.value, ast.Name):
                        src_id = statement.value.id
                        resolved_src = self.resolve_alias(src_id)
                        for target in target_names:
                            self.set_alias(target, src_id)
                            src_flow = flows.get(src_id) or flows.get(resolved_src)
                            if src_flow is not None:
                                flows[target] = src_flow
                            else:
                                flows.pop(target, None)
                    else:
                        for target in target_names:
                            flows.pop(target, None)
                            self.remove_alias(target)
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                target = statement.target.id
                if isinstance(statement.value, (ast.Call, ast.Await)):
                    is_fetch, has_lock = _django_manager_call(statement.value)
                    if is_fetch:
                        flows[target] = _DjangoObjectFlow(
                            fetch=statement.value,
                            row_locked=has_lock,
                            atomic_scopes=frozenset(active_scopes),
                        )
                        self.remove_alias(target)
                    else:
                        flows.pop(target, None)
                        self.remove_alias(target)
                elif isinstance(statement.value, ast.Name):
                    src_id = statement.value.id
                    resolved_src = self.resolve_alias(src_id)
                    self.set_alias(target, src_id)
                    src_flow = flows.get(src_id) or flows.get(resolved_src)
                    if src_flow is not None:
                        flows[target] = src_flow
                    else:
                        flows.pop(target, None)
                else:
                    flows.pop(target, None)
                    self.remove_alias(target)

            mutation_targets: list[ast.AST] = []
            if isinstance(statement, ast.AugAssign):
                has_f_call = any(
                    isinstance(c, ast.Call) and _expr_name(c) in {"F", "models.F", "django.db.models.F"}
                    for c in ast.walk(statement.value)
                )
                if not has_f_call:
                    mutation_targets.append(statement.target)
            elif isinstance(statement, ast.Assign):
                has_f_call = any(
                    isinstance(c, ast.Call) and _expr_name(c) in {"F", "models.F", "django.db.models.F"}
                    for c in ast.walk(statement.value)
                )
                if not has_f_call:
                    mutation_targets.extend(
                        target for target in statement.targets if isinstance(target, (ast.Attribute, ast.Subscript))
                    )

            for mutation_target in mutation_targets:
                root = _target_root_name(mutation_target)
                resolved_root = self.resolve_alias(root)
                flow = flows.get(root) or flows.get(resolved_root)
                if flow is not None:
                    flow.mutated = True
                    if not protected(flow, active_scopes) and not flow.reported:
                        flow.reported = True
                        self._add(
                            "CG-016",
                            flow.fetch,
                            node.name,
                            "Django Unlocked Read-Modify-Write: a model fetched through objects is mutated and saved without a row lock held by transaction.atomic().",
                            "Fetch the row with '.objects.select_for_update().get(...)' (or before filter().first()) inside transaction.atomic().",
                        )
                        return True

            for call in calls(statement):
                if not isinstance(call.func, ast.Attribute) or call.func.attr not in {"save", "asave"}:
                    continue
                root = _target_root_name(call.func.value)
                resolved_root = self.resolve_alias(root)
                flow = flows.get(root) or flows.get(resolved_root)
                if flow is not None and flow.mutated and not protected(flow, active_scopes) and not flow.reported:
                    flow.reported = True
                    self._add(
                        "CG-016",
                        flow.fetch,
                        node.name,
                        "Django Unlocked Read-Modify-Write: a model fetched through objects is mutated and saved without a row lock held by transaction.atomic().",
                        "Fetch the row with '.objects.select_for_update().get(...)' (or before filter().first()) inside transaction.atomic().",
                    )
                    return True
            return False

        def analyze_block(
            statements: list[ast.stmt], active_scopes: tuple[int, ...], flows: dict[str, _DjangoObjectFlow]
        ) -> bool:
            for statement in statements:
                if isinstance(statement, (ast.With, ast.AsyncWith)):
                    self.context_stack.append(statement)
                    added_scopes = tuple(
                        id(item.context_expr)
                        for item in statement.items
                        if is_atomic_context(item.context_expr)
                    )
                    res = analyze_block(
                        statement.body,
                        active_scopes + added_scopes,
                        clone(flows),
                    )
                    self.context_stack.pop()
                    if res:
                        return True
                elif isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                    if analyze_block(statement.body, active_scopes, clone(flows)):
                        return True
                    if analyze_block(statement.orelse, active_scopes, clone(flows)):
                        return True
                elif isinstance(statement, ast.Try):
                    branches = [statement.body, statement.orelse, statement.finalbody] + [handler.body for handler in statement.handlers]
                    if any(analyze_block(branch, active_scopes, clone(flows)) for branch in branches):
                        return True
                elif analyze_statement(statement, active_scopes, flows):
                    return True
            return False

        analyze_block(node.body, (), {})

    def _check_cg_017(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-017: Suggest atomic F() expression for in-memory arithmetic on Django model.

        When a Django model's numeric attribute is modified with simple arithmetic (+, -, *)
        and then saved via save() or asave(), an atomic database F() expression should be
        preferred to avoid race conditions and lock contention.
        """
        django_fetched_vars: dict[str, tuple[ast.AST, str]] = {}
        arithmetic_mutated_vars: set[str] = set()

        for stmt in local_nodes:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                val = stmt.value
                targets: list[str] = []
                if isinstance(stmt, ast.Assign):
                    targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    targets = [stmt.target.id]

                if val is not None and isinstance(val, (ast.Call, ast.Await)):
                    is_fetch, _ = _django_manager_call(val)
                    if is_fetch:
                        model_name = _expr_name(val)
                        for t in targets:
                            django_fetched_vars[t] = (val, model_name)
                elif val is not None and isinstance(val, ast.Name):
                    resolved_val = self.resolve_alias(val.id)
                    if val.id in django_fetched_vars:
                        for t in targets:
                            django_fetched_vars[t] = django_fetched_vars[val.id]
                    elif resolved_val in django_fetched_vars:
                        for t in targets:
                            django_fetched_vars[t] = django_fetched_vars[resolved_val]

            # Check for AugAssign: product.stock -= 1
            if (
                isinstance(stmt, ast.AugAssign)
                and isinstance(stmt.target, ast.Attribute)
                and isinstance(stmt.op, (ast.Add, ast.Sub, ast.Mult))
            ):
                has_f = any(
                    isinstance(c, ast.Call) and _expr_name(c) in {"F", "models.F", "django.db.models.F"}
                    for c in ast.walk(stmt.value)
                )
                if not has_f:
                    root = _target_root_name(stmt.target)
                    resolved_root = self.resolve_alias(root)
                    if root in django_fetched_vars or resolved_root in django_fetched_vars:
                        arithmetic_mutated_vars.add(root)
                        arithmetic_mutated_vars.add(resolved_root)

            # Check for Assign with BinOp: product.stock = product.stock - 1
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Attribute)
                and isinstance(stmt.value, ast.BinOp)
                and isinstance(stmt.value.op, (ast.Add, ast.Sub, ast.Mult))
            ):
                target = stmt.targets[0]
                has_f = any(
                    isinstance(c, ast.Call) and _expr_name(c) in {"F", "models.F", "django.db.models.F"}
                    for c in ast.walk(stmt.value)
                )
                if not has_f:
                    root = _target_root_name(target)
                    resolved_root = self.resolve_alias(root)
                    if root in django_fetched_vars or resolved_root in django_fetched_vars:
                        arithmetic_mutated_vars.add(root)
                        arithmetic_mutated_vars.add(resolved_root)

            # Check for save() or asave()
            for call in (n for n in ast.walk(stmt) if isinstance(n, ast.Call)):
                if isinstance(call.func, ast.Attribute) and call.func.attr in {"save", "asave"}:
                    root = _target_root_name(call.func.value)
                    resolved_root = self.resolve_alias(root)
                    target_var = (
                        root if root in arithmetic_mutated_vars
                        else (resolved_root if resolved_root in arithmetic_mutated_vars else None)
                    )
                    if target_var and target_var in django_fetched_vars:
                        self._add(
                            "CG-017",
                            stmt,
                            node.name,
                            "Django non-atomic in-memory arithmetic: model attribute is updated in Python memory before save() instead of using an atomic database F() expression.",
                            "Use 'Model.objects.filter(...).update(field=F(\"field\") +/- amount)' for atomic, lock-free database updates.",
                        )
                        arithmetic_mutated_vars.discard(target_var)

    def _check_cg_018(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-018: Detect unsafe distributed lock release via raw delete().

        In distributed locking (e.g. Redis), releasing a lock via client.delete(lock_key)
        without validating token ownership can release another worker's expired lock.
        """
        for stmt in local_nodes:
            if not isinstance(stmt, ast.Call):
                continue
            if not isinstance(stmt.func, ast.Attribute) or stmt.func.attr != "delete":
                continue

            caller_name = _expr_name(stmt.func.value).lower()
            is_redis_client = any(
                k in caller_name for k in ("redis", "client", "cache", "redlock", "conn")
            ) or caller_name in ("r", "rd", "rc")

            if not is_redis_client and caller_name:
                continue

            is_lock_delete = False
            for arg in stmt.args:
                arg_name = _expr_name(arg).lower()
                if "lock" in arg_name:
                    is_lock_delete = True
                    break
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if "lock" in arg.value.lower():
                        is_lock_delete = True
                        break
                elif isinstance(arg, ast.BinOp):
                    for child in ast.walk(arg):
                        if (
                            isinstance(child, ast.Constant) and isinstance(child.value, str) and "lock" in child.value.lower()
                        ) or (
                            isinstance(child, ast.Name) and "lock" in child.id.lower()
                        ):
                            is_lock_delete = True
                            break
                    if is_lock_delete:
                        break

            if is_lock_delete:
                self._add(
                    "CG-018",
                    stmt,
                    node.name,
                    "Unsafe distributed lock release: deleting lock key directly via delete() without verifying token ownership can release another worker's expired lock.",
                    "Release distributed locks using a token-checked Lua script or use Redis.lock() / Redlock context manager.",
                )

    def _check_cg_019(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-019: Detect request-scoped database session passed to BackgroundTasks.

        FastAPI BackgroundTasks execute after the response has been sent and the dependency
        context has closed the database session. Passing a request-scoped db session causes
        connection pool errors and concurrent session use.
        """
        session_var_names = {"db", "session", "db_session", "session_factory", "async_session", "session_maker"}
        for stmt in local_nodes:
            if not isinstance(stmt, ast.Call):
                continue
            if not isinstance(stmt.func, ast.Attribute) or stmt.func.attr != "add_task":
                continue

            caller_name = _expr_name(stmt.func.value).lower()
            if not any(k in caller_name for k in ("background", "tasks", "task")):
                continue

            passed_args = stmt.args[1:]
            found = False
            for arg in passed_args:
                name = _expr_name(arg).lower()
                if name in session_var_names or "session" in name or name == "db":
                    self._add(
                        "CG-019",
                        stmt,
                        node.name,
                        "FastAPI BackgroundTasks session leak: request-scoped database session passed to background task outlives request lifecycle.",
                        "Instantiate a new dedicated database session inside the background task function instead of passing the request-scoped session.",
                    )
                    found = True
                    break

            if not found:
                for kw in stmt.keywords:
                    kw_val = _expr_name(kw.value).lower()
                    if kw.arg in session_var_names or kw_val in session_var_names or "session" in kw_val:
                        self._add(
                            "CG-019",
                            stmt,
                            node.name,
                            "FastAPI BackgroundTasks session leak: request-scoped database session passed to background task outlives request lifecycle.",
                            "Instantiate a new dedicated database session inside the background task function instead of passing the request-scoped session.",
                        )
                        break

    def _check_cg_020(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-020: Detect unbounded lock held across external network I/O.

        Executing external HTTP or network calls while holding a synchronization lock
        or active database transaction exhausts connection pools and causes high lock contention.
        """
        network_call_prefixes = (
            "requests.get", "requests.post", "requests.put", "requests.delete", "requests.request", "requests.patch",
            "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request", "httpx.patch",
            "urllib.request.urlopen",
            "client.get", "client.post", "client.put", "client.delete", "client.request",
            "http_client.get", "http_client.post", "http_client.request",
        )

        def is_network_call(call_node: ast.Call) -> bool:
            if not isinstance(call_node.func, (ast.Attribute, ast.Name)):
                return False
            if isinstance(call_node.func, ast.Attribute) and isinstance(call_node.func.value, ast.Call):
                return False
            name = _expr_name(call_node.func).lower()
            return any(name == prefix or name.endswith("." + prefix) for prefix in network_call_prefixes)

        for with_stmt in (n for n in local_nodes if isinstance(n, (ast.With, ast.AsyncWith))):
            is_locked_context = False
            for item in with_stmt.items:
                ctx_name = _expr_name(item.context_expr).lower()
                if "atomic" in ctx_name or "lock" in ctx_name or "semaphore" in ctx_name:
                    is_locked_context = True
                    break

            if not is_locked_context:
                continue

            for child in ast.walk(with_stmt):
                if isinstance(child, ast.Call) and is_network_call(child):
                    self._add(
                        "CG-020",
                        child,
                        node.name,
                        "Unbounded lock held across network I/O: external HTTP/network request executed while holding lock or database transaction.",
                        "Perform external network I/O before acquiring the lock or database transaction, or use a two-phase reservation pattern.",
                    )

    def _check_cg_021(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-021: Detect generator/coroutine lock leak ('yield' inside locked context).

        Yielding inside a lock context keeps the lock held across generator suspension points.
        If the consumer slows down, blocks, or abandons the generator, the lock is held indefinitely.
        """
        for with_stmt in (n for n in local_nodes if isinstance(n, (ast.With, ast.AsyncWith))):
            is_lock = False
            for item in with_stmt.items:
                if _is_lock_expr(item.context_expr):
                    is_lock = True
                    break

            if not is_lock:
                continue

            for child in ast.walk(with_stmt):
                if isinstance(child, (ast.Yield, ast.YieldFrom)):
                    self._add(
                        "CG-021",
                        child,
                        node.name,
                        "Generator lock leak: 'yield' inside locked context keeps lock held across generator suspension points.",
                        "Acquire the lock inside the loop per item, or consume items into a local list under lock before yielding.",
                    )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect sync function definitions for rule CG-005."""
        saved_aliases, saved_context = self.aliases, self.context_stack
        self.aliases, self.context_stack = {}, []
        try:
            local_nodes = list(_walk_local_nodes(node, include_self=False))
            self._check_cg_005(node, local_nodes)
            self._check_cg_016(node, local_nodes)
            self._check_cg_017(node, local_nodes)
            self._check_cg_018(node, local_nodes)
            self._check_cg_019(node, local_nodes)
            self._check_cg_020(node, local_nodes)
            self._check_cg_021(node, local_nodes)
            self._check_standard_library_rules(node, local_nodes)
            self.generic_visit(node)
        finally:
            self.aliases, self.context_stack = saved_aliases, saved_context

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Inspect async function definitions for rules CG-001, CG-002, CG-003, CG-004, CG-005, and CG-013."""
        saved_aliases, saved_context = self.aliases, self.context_stack
        self.aliases, self.context_stack = {}, []
        try:
            local_nodes = list(_walk_local_nodes(node, include_self=False))
            self._check_cg_001(node, local_nodes)
            self._check_cg_002(node, local_nodes)
            self._check_cg_003(node)
            self._check_cg_004(node, local_nodes)
            self._check_cg_005(node, local_nodes)
            self._check_cg_016(node, local_nodes)
            self._check_cg_017(node, local_nodes)
            self._check_cg_018(node, local_nodes)
            self._check_cg_019(node, local_nodes)
            self._check_cg_020(node, local_nodes)
            self._check_cg_021(node, local_nodes)
            self._check_standard_library_rules(node, local_nodes)

            # Check for synchronous locks acquired inside async coroutine
            for with_node in (n for n in local_nodes if isinstance(n, ast.With)):
                for item in with_node.items:
                    if _is_lock_expr(item.context_expr):
                        lock_name = _expr_name(item.context_expr) or "lock"
                        has_await_inside = any(
                            isinstance(child, (ast.Await, ast.AsyncFor, ast.AsyncWith))
                            for child in ast.walk(with_node)
                        )
                        if has_await_inside:
                            self.findings.append(
                                ASTFinding(
                                    rule_id="CG-013",
                                    filename=self.filename,
                                    lineno=with_node.lineno,
                                    function_name=node.name,
                                    message=(
                                        f"Potential event loop deadlock: synchronous lock '{lock_name}' "
                                        f"held across 'await' boundary in coroutine '{node.name}'."
                                    ),
                                    suggested_fix_hint=(
                                        f"Replace synchronous lock '{lock_name}' with 'async with asyncio.Lock()' "
                                        "to prevent deadlocking other coroutines waiting for the event loop."
                                    ),
                                )
                            )
                        else:
                            self.findings.append(
                                ASTFinding(
                                    rule_id="CG-013",
                                    filename=self.filename,
                                    lineno=with_node.lineno,
                                    function_name=node.name,
                                    message=(
                                        f"Blocking synchronization in async coroutine: synchronous lock '{lock_name}' "
                                        f"acquired via 'with' inside coroutine '{node.name}'."
                                    ),
                                    suggested_fix_hint=(
                                        "Use 'async with asyncio.Lock()' instead of synchronous threading.Lock "
                                        "to avoid blocking the event loop thread."
                                    ),
                                )
                            )

            self.generic_visit(node)
        finally:
            self.aliases, self.context_stack = saved_aliases, saved_context


def _custom_rule_findings(tree: ast.AST, filename: str, rules: list[dict[str, Any]]) -> list[ASTFinding]:
    """Evaluate compact YAML rules against functions without executing YAML content.

    Supported fields are ``id``/``rule_id``, ``function`` (called dotted name),
    ``modifies`` (target text), and ``without_context`` (required context text).
    A rule matches when all supplied positive predicates match and its context is
    absent. This intentionally small DSL is predictable and safe to extend.
    """
    findings: list[ASTFinding] = []
    for function in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        nodes = list(_walk_local_nodes(function, include_self=False))
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


def scan_file(
    file_path: Path,
    custom_rules: Optional[list[dict[str, Any]]] = None,
    cache_manager: Optional[Any] = None,
    suppression_filter: Optional[SuppressionFilter] = None,
) -> list[ASTFinding]:
    """Scan a Python file for concurrency vulnerabilities, skipping unparseable files."""
    if cache_manager is not None:
        cached = cache_manager.get_cached_findings(file_path)
        if cached is not None:
            from concurrency_guard.cache.manager import dict_to_finding

            findings = [dict_to_finding(d) for d in cached]
            if suppression_filter is not None:
                return suppression_filter.filter_findings(findings, file_path=file_path)
            return SuppressionFilter().filter_findings(findings, file_path=file_path)

    try:
        source_code = file_path.read_text(encoding="utf-8-sig")
    except (UnicodeDecodeError, OSError):
        return []

    try:
        findings = scan_source_code(source_code, filename=str(file_path), custom_rules=custom_rules)
    except (SyntaxError, ValueError):
        findings = []

    if cache_manager is not None:
        from concurrency_guard.cache.manager import finding_to_dict

        cache_manager.update_cache(file_path, [finding_to_dict(f) for f in findings])

    filter_obj = suppression_filter or SuppressionFilter()
    filter_obj.parse_source(source_code, filepath=file_path)
    return filter_obj.filter_findings(findings, file_path=file_path)


def scan_directory(
    dir_path: Path,
    custom_rules: Optional[list[dict[str, Any]]] = None,
    cache_manager: Optional[Any] = None,
    suppression_filter: Optional[SuppressionFilter] = None,
    workers: Optional[int] = None,
) -> list[ASTFinding]:
    """Scan a directory recursively, including cross-file call-chain analysis."""
    return scan_project(
        discover_python_files(dir_path),
        roots=[dir_path],
        custom_rules=custom_rules,
        cache_manager=cache_manager,
        suppression_filter=suppression_filter,
        workers=workers,
    )


def scan_project(
    file_paths: list[Path],
    roots: Optional[list[Path]] = None,
    custom_rules: Optional[list[dict[str, Any]]] = None,
    cache_manager: Optional[Any] = None,
    suppression_filter: Optional[SuppressionFilter] = None,
    workers: Optional[int] = None,
) -> list[ASTFinding]:
    """Scan files and propagate shared-state hazards to transitive callers.

    CG-014 reports at a public caller when its cross-file call chain reaches a
    function that mutates module shared state. Graph construction reads source
    only; no scanned code is imported or executed.
    """
    active_filter = suppression_filter or SuppressionFilter()

    findings: list[ASTFinding] = []
    effective_workers = workers if workers and workers > 1 else (min(8, len(file_paths)) if len(file_paths) > 2 else 1)
    if effective_workers > 1:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_workers) as executor:
            future_to_file = {
                executor.submit(
                    scan_file,
                    file_path,
                    custom_rules=custom_rules,
                    cache_manager=cache_manager,
                    suppression_filter=active_filter,
                ): file_path
                for file_path in file_paths
            }
            for future in concurrent.futures.as_completed(future_to_file):
                findings.extend(future.result())
    else:
        for file_path in file_paths:
            findings.extend(
                scan_file(
                    file_path,
                    custom_rules=custom_rules,
                    cache_manager=cache_manager,
                    suppression_filter=active_filter,
                )
            )
    graph = build_call_graph(file_paths, roots=roots)
    taint_findings = find_tainted_shared_state_mutations(file_paths, graph)
    for finding in taint_findings:
        if not active_filter.should_suppress("CG-015", Path(finding.filename), finding.lineno):
            findings.append(
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
            )
        else:
            active_filter.suppressed_count += 1

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
            if not active_filter.should_suppress("CG-014", Path(caller.filename), caller.lineno):
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
            else:
                active_filter.suppressed_count += 1

    return list(dict.fromkeys(findings))

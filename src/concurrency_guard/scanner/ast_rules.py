"""AST scanning rules for concurrency and idempotency vulnerabilities."""

from __future__ import annotations

import ast
import os
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import yaml

from concurrency_guard.cfg import mutation_protection
from concurrency_guard.scanner.call_graph import (
    FunctionSummary,
    analyze_module_functions,
)
from concurrency_guard.scanner.suppression import SuppressionFilter
from concurrency_guard.scanner.taint_tracker import (
    find_tainted_shared_state_mutations_in_source,
)
from concurrency_guard.shared_state import shared_writes

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
    ".cguard_cache",
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
    col_offset: Optional[int] = None



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


def _is_lock_expr(
    node: ast.AST,
    custom_lock_names: Optional[Union[list[str], set[str]]] = None,
) -> bool:
    name = _expr_name(node).lower()
    if custom_lock_names:
        for cname in custom_lock_names:
            c_low = cname.lower()
            if c_low in name:
                return True
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and c_low in child.id.lower():
                    return True
                if isinstance(child, ast.Attribute) and c_low in child.attr.lower():
                    return True
    return any(k in name for k in ("lock", "semaphore", "mutex", "advisory_lock", "redis_lock", "redlock"))


_SCOPE_BOUNDARY_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _walk_local_nodes(node: ast.AST, include_self: bool = True) -> Iterator[ast.AST]:
    """Walk node and child nodes without descending into nested function definitions, classes, or lambdas."""
    if include_self:
        yield node
    for child in ast.iter_child_nodes(node):
        if not isinstance(child, _SCOPE_BOUNDARY_TYPES):
            yield from _walk_local_nodes(child, include_self=True)


def _get_lock_spans(
    node: ast.AST,
    custom_lock_names: Optional[Union[list[str], set[str]]] = None,
) -> list[tuple[int, int]]:
    """Return (start_line, end_line) spans for all with/async-with statements holding locks."""
    spans: list[tuple[int, int]] = []
    for child in _walk_local_nodes(node, include_self=isinstance(node, (ast.With, ast.AsyncWith))):
        if isinstance(child, (ast.With, ast.AsyncWith)):
            for item in child.items:
                if _is_lock_expr(item.context_expr, custom_lock_names=custom_lock_names):
                    start = child.lineno
                    end = getattr(child, "end_lineno", None)
                    if end is None:
                        end = max([getattr(c, "lineno", start) for c in _walk_local_nodes(child, include_self=True)] + [start])
                    spans.append((start, end))
    return spans


def _lock_names(
    node: ast.AST,
    custom_lock_names: Optional[Union[list[str], set[str]]] = None,
) -> list[str]:
    """Find names held by with/async-with statements, preserving nesting order."""
    names: list[str] = []
    for child in _walk_local_nodes(node, include_self=isinstance(node, (ast.With, ast.AsyncWith))):
        if isinstance(child, (ast.With, ast.AsyncWith)):
            for item in child.items:
                if _is_lock_expr(item.context_expr, custom_lock_names=custom_lock_names):
                    name = _expr_name(item.context_expr)
                    names.append(name or "<lock>")
    return names


def _has_lock_context(
    node: ast.AST,
    custom_lock_names: Optional[Union[list[str], set[str]]] = None,
) -> bool:
    return bool(_lock_names(node, custom_lock_names=custom_lock_names))


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


def _is_tortoise_query(node: ast.AST) -> tuple[bool, bool]:
    """Check if node is a Tortoise ORM model query (e.g. Model.get, Model.filter(...).first()).

    Returns (is_tortoise, has_lock).
    """
    curr = node.value if isinstance(node, ast.Await) else node
    if not isinstance(curr, ast.Call):
        return False, False

    methods: list[str] = []
    has_lock = False
    model_name: Optional[str] = None

    scan_curr: ast.AST = curr
    while True:
        if isinstance(scan_curr, ast.Await):
            scan_curr = scan_curr.value
        elif isinstance(scan_curr, ast.Call):
            if isinstance(scan_curr.func, ast.Attribute):
                attr = scan_curr.func.attr
                methods.append(attr)
                if attr in ("select_for_update", "with_for_update"):
                    has_lock = True
                scan_curr = scan_curr.func.value
            else:
                break
        elif isinstance(scan_curr, ast.Attribute):
            attr = scan_curr.attr
            if attr[0].isupper() and model_name is None:
                model_name = attr
            methods.append(attr)
            scan_curr = scan_curr.value
        elif isinstance(scan_curr, ast.Name):
            if scan_curr.id[0].isupper() and model_name is None:
                model_name = scan_curr.id
            break
        else:
            break

    if model_name is not None:
        tortoise_query_methods = {"get", "get_or_none", "filter", "all", "first", "one", "one_or_none"}
        if any(m in tortoise_query_methods for m in methods) and "objects" not in methods:
            return True, has_lock

    return False, False


def _is_query_call(node: ast.AST) -> bool:
    """Check if node is a select(...) call or SQLAlchemy/SQLModel/Tortoise query."""
    if _is_select_call(node):
        return True
    is_tort, _ = _is_tortoise_query(node)
    if is_tort:
        return True
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr in ("scalar", "scalars", "get", "get_or_none", "all", "first", "one", "one_or_none"):
        return _is_db_or_session(node.func.value)
    return bool(
        node.func.attr in ("execute", "exec")
        and _is_db_or_session(node.func.value)
        and (
            not node.args
            or any(_is_select_call(arg) or any(_is_select_call(c) for c in ast.walk(arg)) for arg in node.args)
        )
    )


def _is_add_call(node: ast.AST) -> bool:
    """Check if node is a db.add(...) or session.add(...) call."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add":
        return _is_db_or_session(node.func.value)
    return False


def _is_commit_call(node: ast.AST) -> bool:
    """Check if node is a .commit() or .save() call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("commit", "save")
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
    """Find db/session execute, exec, scalar, scalars, get, or Tortoise ORM query calls directly within loop bodies."""
    calls: list[ast.Call] = []
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _SCOPE_BOUNDARY_TYPES):
            continue

        if in_loop and isinstance(child, ast.Call):
            matched = False
            if (
                isinstance(child.func, ast.Attribute)
                and child.func.attr in ("execute", "exec", "scalar", "scalars", "get")
                and _is_db_or_session(child.func.value)
            ):
                calls.append(child)
                matched = True
            else:
                is_tort, _ = _is_tortoise_query(child)
                if is_tort:
                    calls.append(child)
                    matched = True

            if matched:
                for arg in child.args:
                    calls.extend(_find_loop_execute_calls(arg, in_loop=True))
                for kw in child.keywords:
                    calls.extend(_find_loop_execute_calls(kw.value, in_loop=True))
                continue

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


def _has_repeatable_row_assignment(node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> bool:
    """Recognize a narrow session.get / literal field assignment / commit pattern.

    Unknown calls, inserts, computed writes and mutations keep their retry diagnostics.
    """
    local_nodes = [child for stmt in node.body for child in _walk_local_nodes(stmt)]
    sessions: set[str] = set()
    entities: set[str] = set()
    wrote = False
    for n in sorted(local_nodes, key=lambda n: getattr(n, "lineno", 0)):
        if isinstance(n, ast.Assign) and len(n.targets) == 1:
            target = n.targets[0]
            if isinstance(target, ast.Name) and isinstance(n.value, ast.Call):
                call = n.value
                if isinstance(call.func, ast.Name) and call.func.id.lower().endswith("sessionlocal"):
                    sessions.add(target.id)
                elif (isinstance(call.func, ast.Attribute) and call.func.attr == "get"
                      and isinstance(call.func.value, ast.Name) and call.func.value.id in sessions):
                    entities.add(target.id)
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name) and n.func.id.lower().endswith("sessionlocal"):
                continue
            if (isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                    and n.func.value.id in sessions and n.func.attr in {"get", "commit", "close", "rollback"}):
                continue
            return False
        if (isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load)
                and isinstance(n.value, ast.Name) and n.value.id in entities):
            return False
        if isinstance(n, (ast.AugAssign, ast.Delete, ast.NamedExpr)):
            return False
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for target in targets:
                if isinstance(target, ast.Attribute):
                    if (not isinstance(target.value, ast.Name) or target.value.id not in entities
                            or not isinstance(n.value, ast.Constant)):
                        return False
                    wrote = True
                elif not isinstance(target, ast.Name):
                    return False
                elif target.id in entities or target.id in sessions:
                    # Rebinding a known receiver to a different expression loses provenance.
                    if not isinstance(n.value, ast.Call):
                        return False
    return wrote


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


def _helper_name(func_expr: ast.AST) -> str:
    """Return the function or method identifier name for a call."""
    if isinstance(func_expr, ast.Name):
        return func_expr.id
    if isinstance(func_expr, ast.Attribute):
        return func_expr.attr
    return ""


class ConcurrencyASTVisitor(ast.NodeVisitor):
    """AST visitor detecting concurrency race conditions and idempotency issues."""

    def __init__(
        self,
        filename: str = "<memory>",
        tree: Optional[ast.AST] = None,
        config: Optional[Any] = None,
        custom_lock_names: Optional[Union[list[str], set[str]]] = None,
        project_graph: Optional[Any] = None,
    ) -> None:
        self.parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        } if tree is not None else {}
        self.local_functions = {
            self._qualified_function(n): n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        } if tree is not None else {}
        self.filename = filename
        self.config = config
        self.project_graph = project_graph
        self.entity_origins: dict[str, str] = {}
        self.custom_lock_names: set[str] = set(custom_lock_names or [])
        if config is not None and hasattr(config, "custom_lock_names"):
            self.custom_lock_names.update(config.custom_lock_names)
        self.findings: list[ASTFinding] = []
        self.shared_names: set[str] = set()
        self.thread_targets: set[str] = set()
        self.lock_orders: list[tuple[str, str, int, str]] = []
        self.aliases: dict[str, str] = {}
        self.context_stack: list[Union[ast.With, ast.AsyncWith]] = []
        self.reentrant_locks: set[str] = set()
        self.function_locks: dict[str, set[str]] = defaultdict(set)
        self.calls_under_lock: list[tuple[str, str, str, int]] = []
        self.function_summaries: dict[str, FunctionSummary] = (
            analyze_module_functions(tree, custom_lock_names=self.custom_lock_names) if isinstance(tree, ast.Module) else {}
        )

    def _qualified_function(self, node: ast.AST) -> str:
        parts = []
        current: Optional[ast.AST] = node
        while current is not None:
            if isinstance(current, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                parts.append(current.name)
            current = self.parents.get(current)
        return ".".join(reversed(parts))

    def _lock_identity(self, name: str, node: ast.AST) -> str:
        if name.startswith(("self.", "cls.")):
            current: Optional[ast.AST] = node
            while current is not None:
                if isinstance(current, ast.ClassDef):
                    return self._qualified_function(current) + "::" + name
                current = self.parents.get(current)
        return name

    def _resolve_locked_call(
        self, caller: Union[ast.FunctionDef, ast.AsyncFunctionDef], call: ast.Call,
    ) -> Optional[str]:
        """Resolve direct local calls without guessing from a receiver's method name."""
        scope = self._qualified_function(caller).split(".")[:-1]
        if isinstance(call.func, ast.Attribute):
            if not isinstance(call.func.value, ast.Name) or call.func.value.id not in {"self", "cls"}:
                return None
            parent = self.parents.get(caller)
            if not isinstance(parent, ast.ClassDef):
                return None
            candidate = ".".join([*scope, call.func.attr])
            return candidate if candidate in self.local_functions else None
        if isinstance(call.func, ast.Name):
            name = call.func.id
            # A parameter or local binding can shadow a function with the same name.
            if any(arg.arg == name for arg in (
                *caller.args.posonlyargs, *caller.args.args, *caller.args.kwonlyargs,
                *([caller.args.vararg] if caller.args.vararg else []),
                *([caller.args.kwarg] if caller.args.kwarg else []),
            )) or any(isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id == name
                      for n in _walk_local_nodes(caller)):
                return None
            for length in range(len(scope) + 1, -1, -1):
                prefix = self._qualified_function(caller).split(".")[:length]
                candidate = ".".join([*prefix, name])
                target = self.local_functions.get(candidate)
                if target is not None and not isinstance(self.parents.get(target), ast.ClassDef):
                    return candidate
        return None

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
            isinstance(ctx, ast.AsyncWith)
            and any(_is_lock_expr(item.context_expr, self.custom_lock_names) for item in ctx.items)
            for ctx in self.context_stack
        )

    def is_in_sync_lock(self) -> bool:
        """Return True if currently inside an active with lock/semaphore block."""
        return any(
            isinstance(ctx, ast.With)
            and any(_is_lock_expr(item.context_expr, self.custom_lock_names) for item in ctx.items)
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
                    self.reentrant_locks.add(self._lock_identity(tname, node))
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
                    self.reentrant_locks.add(self._lock_identity(tname, node))
        if isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Name):
                self.set_alias(node.target.id, node.value.id)
            else:
                self.remove_alias(node.target.id)
        self.generic_visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        """Collect module shared state and thread entry points before functions."""
        if not self.function_summaries:
            self.function_summaries = analyze_module_functions(node, custom_lock_names=self.custom_lock_names)
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
                col_offset=getattr(node, "col_offset", 0),
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
                    self.function_locks[self._qualified_function(node)].add(self._lock_identity(lname, node))
            for call_child in (n for n in _walk_local_nodes(with_node) if isinstance(n, ast.Call)):
                callee = self._resolve_locked_call(node, call_child)
                if callee is not None:
                    for olock in outer:
                        if olock:
                            self.calls_under_lock.append((
                                self._qualified_function(node),
                                self._lock_identity(olock, node), callee, call_child.lineno,
                            ))

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

    def _check_cg_001(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]) -> None:
        """Rule CG-001: Unlocked Read-Modify-Write Race Condition."""
        # 1. Fast check: must have a commit, flush, or save call
        has_commit = any(
            _is_commit_call(n)
            or (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("commit", "flush", "save")
            )
            or (
                isinstance(n, ast.Call)
                and _helper_name(n.func) in self.function_summaries
                and self.function_summaries[_helper_name(n.func)].performs_commit
            )
            or (
                isinstance(n, ast.Call)
                and self.project_graph is not None
                and (self.project_graph.resolve_call(self.filename, n) is not None)
                and self.project_graph.resolve_call(self.filename, n)[0].performs_commit
            )
            for n in local_nodes
        )
        if not has_commit:
            return

        protected, partial, live, unlocked = mutation_protection(node)
        for statement in local_nodes:
            if id(statement) in partial:
                self._add("CG-028", statement, node.name,
                          f"Partial-path unlocked mutation of '{partial[id(statement)]}' before commit.",
                          "Acquire the same lock on every path to the mutation.")
        if not isinstance(node, ast.AsyncFunctionDef):
            return

        # 2. Collect lock spans: statements inside locks are safe
        lock_spans = _get_lock_spans(node, custom_lock_names=self.custom_lock_names)

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
            """Unwind result proxy method chain (.scalars().all(), .scalar_one(), .first(), etc.) to the underlying db.execute() or session.exec() call."""
            curr = call_node
            while isinstance(curr, ast.Call) and isinstance(curr.func, ast.Attribute):
                if curr.func.attr in ("execute", "exec") and _is_db_or_session(curr.func.value):
                    return curr
                if curr.func.attr in ("scalar", "scalars", "scalar_one", "scalar_one_or_none", "first", "one", "one_or_none", "all"):
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

            # Check Tortoise ORM model queries (e.g. Model.get, Model.filter(...).first())
            is_tort, tort_locked = _is_tortoise_query(unwrapped)
            if is_tort:
                q_line = getattr(unwrapped, "lineno", stmt_lineno)
                q_end = max(getattr(unwrapped, "end_lineno", q_line), stmt_end_lineno)
                for t in targets:
                    for name in _extract_names(t):
                        entity_sources[name] = (unwrapped, q_line, q_end, tort_locked)

            # Check A0: Local or cross-file helper function returning locked or unlocked entity
            if isinstance(unwrapped, ast.Call):
                callee_name = _helper_name(unwrapped.func)
                callee_sum: Optional[FunctionSummary] = None
                origin_desc = ""

                if self.project_graph is not None:
                    pg_res = self.project_graph.resolve_call(self.filename, unwrapped)
                    if pg_res is not None:
                        callee_sum, origin_file, symbol_name = pg_res
                        origin_desc = f" (via {symbol_name} in {Path(origin_file).name})"

                if callee_sum is None and callee_name in self.function_summaries:
                    callee_sum = self.function_summaries[callee_name]

                if callee_sum is not None:
                    call_line = getattr(unwrapped, "lineno", stmt_lineno)
                    call_end = max(getattr(unwrapped, "end_lineno", call_line), stmt_end_lineno)
                    if callee_sum.returns_locked_entity:
                        for t in targets:
                            for name in _extract_names(t):
                                entity_sources[name] = (unwrapped, call_line, call_end, True)
                    elif callee_sum.returns_unlocked_entity:
                        for t in targets:
                            for name in _extract_names(t):
                                entity_sources[name] = (unwrapped, call_line, call_end, False)
                                if origin_desc:
                                    self.entity_origins[name] = origin_desc

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

                elif is_db and attr in ("execute", "exec"):
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

                elif attr in ("scalar", "scalars", "scalar_one", "scalar_one_or_none", "first", "one", "one_or_none", "all"):
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
            if id(stmt) not in live or id(stmt) in protected or id(stmt) in partial or is_locked_line(stmt_line):
                continue

            # Case A: AugAssign, e.g. user.balance -= amount
            if isinstance(stmt, ast.AugAssign):
                root = _target_root_name(stmt.target)
                if root in entity_sources:
                    _, q_line, q_end_line, q_db_locked = entity_sources[root]
                    if not q_db_locked or id(stmt) in unlocked:
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
                                if not q_db_locked or id(stmt) in unlocked:
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
                        if not q_db_locked or id(stmt) in unlocked:
                            reported_entities.add((root, q_line, q_end_line))

            # Case D: Mutating helper calls, e.g. debit_account(user, 50) or await debit_account(user, 50)
            call_obj: Optional[ast.Call] = None
            if isinstance(stmt, ast.Expr):
                expr_val = stmt.value.value if isinstance(stmt.value, ast.Await) else stmt.value
                if isinstance(expr_val, ast.Call):
                    call_obj = expr_val
            elif isinstance(stmt, ast.Call):
                call_obj = stmt
            elif isinstance(stmt, ast.Await) and isinstance(stmt.value, ast.Call):
                call_obj = stmt.value

            if call_obj is not None:
                callee_name = _helper_name(call_obj.func)
                mut_callee_sum: Optional[FunctionSummary] = None
                if self.project_graph is not None:
                    pg_res = self.project_graph.resolve_call(self.filename, call_obj)
                    if pg_res is not None:
                        mut_callee_sum = pg_res[0]
                if mut_callee_sum is None and callee_name in self.function_summaries:
                    mut_callee_sum = self.function_summaries[callee_name]

                if mut_callee_sum is not None and not mut_callee_sum.acquires_lock_context:
                    for arg_idx, arg in enumerate(call_obj.args):
                        root = _target_root_name(arg)
                        if root in entity_sources and arg_idx in mut_callee_sum.mutated_param_indices:
                            _, q_line, q_end_line, q_db_locked = entity_sources[root]
                            if not q_db_locked or id(stmt) in unlocked:
                                reported_entities.add((root, q_line, q_end_line))
                    for kw in call_obj.keywords:
                        if kw.arg:
                            root = _target_root_name(kw.value)
                            if root in entity_sources and kw.arg in mut_callee_sum.mutated_param_names:
                                _, q_line, q_end_line, q_db_locked = entity_sources[root]
                                if not q_db_locked or id(stmt) in unlocked:
                                    reported_entities.add((root, q_line, q_end_line))

        # 5. Emit findings with HIGH confidence
        reported_lines: set[int] = set()
        for root_name, q_line, q_end_line in sorted(reported_entities, key=lambda x: x[1]):
            if q_line not in reported_lines:
                reported_lines.add(q_line)
                origin_ctx = self.entity_origins.get(root_name, "")
                self.findings.append(
                    ASTFinding(
                        rule_id="CG-001",
                        filename=self.filename,
                        lineno=q_line,
                        function_name=node.name,
                        message=(
                            "Unlocked Read-Modify-Write Race Condition: database state is read and "
                            f"mutated without '.with_for_update()' lock before commit{origin_ctx}."
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

        for n in local_nodes:
            if isinstance(n, ast.Call):
                hname = _helper_name(n.func)
                sumry: Optional[FunctionSummary] = None
                if self.project_graph is not None:
                    pg_res = self.project_graph.resolve_call(self.filename, n)
                    if pg_res is not None:
                        sumry = pg_res[0]
                if sumry is None and hname in self.function_summaries:
                    sumry = self.function_summaries[hname]
                if sumry is not None:
                    if sumry.returns_unlocked_entity or sumry.returns_locked_entity:
                        query_calls.append(n)
                    if sumry.performs_commit:
                        commit_calls.append(n)

        query_calls.sort(key=lambda x: getattr(x, "lineno", 0))
        add_calls.sort(key=lambda x: getattr(x, "lineno", 0))
        commit_calls.sort(key=lambda x: getattr(x, "lineno", 0))

        if query_calls and add_calls and commit_calls:
            first_query = query_calls[0]
            first_add = add_calls[0]
            last_commit = commit_calls[-1]

            if first_query.lineno <= first_add.lineno and not _is_commit_protected(node):
                lock_spans = _get_lock_spans(node, custom_lock_names=self.custom_lock_names)
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

        for dec in node.decorator_list:
            if _is_celery_task(dec):
                matching_task_dec = dec
                if _has_celery_retry_kwarg(dec):
                    has_retry = True

        if not matching_task_dec or not has_retry:
            return

        docstring = ast.get_docstring(node)
        if _has_repeatable_row_assignment(node) or _has_idempotency_or_lock(local_nodes, docstring=docstring):
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
                        "executes side effects that may repeat without an idempotency guard."
                    ),
                    suggested_fix_hint=(
                        "Persist an idempotency key and its result atomically with the database changes. "
                        "Use provider idempotency keys for external requests. Late acknowledgment (acks_late=True) "
                        "changes delivery timing and can still repeat side effects."
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

    # -- Distributed Task Queue & Transaction Boundary Rules (CG-022..CG-024) --

    def _check_cg_022(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-022: Premature Background Task Dispatch Before Commit (Transactional Outbox Race).

        Pattern A (SQLAlchemy/SQLModel): Inside a function that writes to DB and calls commit()
        (or inside session.begin() block), flag any task dispatch (.delay/.apply_async/.send/enqueue_job/add_task)
        whose line occurs BEFORE the commit() call (or inside session.begin()).

        Pattern B (Django): Flag .delay()/.apply_async() inside transaction.atomic() (or inside
        a function decorated with @transaction.atomic) unless wrapped in transaction.on_commit().

        Sanitizers:
        - Task dispatched after commit()
        - Task wrapped in transaction.on_commit(...)
        - Read-only function with no DB writes/commits
        """
        _DISPATCH_ATTRS: frozenset[str] = frozenset({
            "delay", "apply_async", "send", "send_with_options",
        })
        _DISPATCH_FUNCS: frozenset[str] = frozenset({
            "enqueue_job",
        })

        def _is_task_dispatch(n: ast.AST) -> bool:
            if not isinstance(n, ast.Call):
                return False
            if isinstance(n.func, ast.Attribute) and n.func.attr in _DISPATCH_ATTRS:
                return True
            if isinstance(n.func, ast.Name) and n.func.id in _DISPATCH_FUNCS:
                return True
            # background_tasks.add_task(...)
            return bool(
                isinstance(n.func, ast.Attribute)
                and n.func.attr == "add_task"
                and isinstance(n.func.value, ast.Name)
                and "task" in n.func.value.id.lower()
            )

        def _is_db_write(n: ast.AST) -> bool:
            """Check for session.add, db.add, session.execute(insert/update), or entity mutation."""
            if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Attribute):
                return False
            attr = n.func.attr
            if attr in ("add", "add_all", "merge", "bulk_save_objects"):
                return _is_db_or_session(n.func.value)
            if attr in ("execute", "exec") and _is_db_or_session(n.func.value):
                # Check if executing an insert/update (not select)
                for arg in n.args:
                    for child in ast.walk(arg):
                        if (
                            isinstance(child, ast.Call)
                            and isinstance(child.func, ast.Name)
                            and child.func.id in ("insert", "update", "delete")
                        ):
                            return True
                        if (
                            isinstance(child, ast.Call)
                            and isinstance(child.func, ast.Attribute)
                            and child.func.attr in ("insert", "update", "delete")
                        ):
                            return True
                return False
            return False

        # Collect all expressions wrapped in transaction.on_commit(...)
        on_commit_calls: set[int] = set()
        for n in local_nodes:
            if isinstance(n, ast.Call):
                func_name = _expr_name(n.func).lower()
                if func_name.endswith("on_commit") or func_name == "on_commit":
                    for sub in ast.walk(n):
                        if sub is not n:
                            on_commit_calls.add(id(sub))

        reported_dispatches: set[int] = set()

        # -- Pattern A: SQLAlchemy/SQLModel pre-commit dispatch --
        db_writes = [n for n in local_nodes if isinstance(n, ast.Call) and _is_db_write(n)]
        commit_calls = [n for n in local_nodes if _is_commit_call(n)]
        dispatches = [n for n in local_nodes if _is_task_dispatch(n) and id(n) not in on_commit_calls]

        # Also detect entity attribute mutations (e.g. order.status = "paid")
        has_entity_mutation = any(
            isinstance(n, (ast.Assign, ast.AugAssign))
            and (
                (isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Attribute))
                or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) for t in n.targets))
            )
            for n in local_nodes
        )

        has_db_writes = bool(db_writes) or has_entity_mutation

        if has_db_writes and commit_calls and dispatches:
            first_commit_line = min(getattr(c, "lineno", 0) for c in commit_calls)
            for dispatch in dispatches:
                dispatch_line = getattr(dispatch, "lineno", 0)
                if dispatch_line < first_commit_line and id(dispatch) not in reported_dispatches:
                    reported_dispatches.add(id(dispatch))
                    self._add(
                        "CG-022",
                        dispatch,
                        node.name,
                        "Premature background task dispatch before commit: task may execute "
                        "while database transaction has not yet committed, causing the task "
                        "to read stale or non-existent data (Transactional Outbox Race).",
                        "Move the task dispatch call (.delay()/.apply_async()/.send()) "
                        "after the db.commit() / await db.commit() call, or use a "
                        "transactional outbox pattern.",
                    )

        # -- session.begin() blocks (SQLAlchemy context manager) --
        for with_stmt in (n for n in local_nodes if isinstance(n, (ast.With, ast.AsyncWith))):
            is_session_begin = any(
                ".begin" in _expr_name(item.context_expr).lower()
                or (isinstance(item.context_expr, ast.Call) and ".begin" in _expr_name(item.context_expr.func).lower())
                for item in with_stmt.items
            )
            if is_session_begin:
                for child in ast.walk(with_stmt):
                    if (
                        isinstance(child, ast.Call)
                        and _is_task_dispatch(child)
                        and id(child) not in on_commit_calls
                        and id(child) not in reported_dispatches
                    ):
                        reported_dispatches.add(id(child))
                        self._add(
                            "CG-022",
                            child,
                            node.name,
                            "Premature background task dispatch inside session.begin(): task dispatched "
                            "inside transaction block before commit (Transactional Outbox Race).",
                            "Move the task dispatch call outside the session.begin() block "
                            "so it executes only after the transaction has successfully committed.",
                        )

        # -- Pattern B: Django transaction.atomic() pre-commit dispatch --
        for with_stmt in (n for n in local_nodes if isinstance(n, (ast.With, ast.AsyncWith))):
            is_atomic = False
            for item in with_stmt.items:
                ctx_name = _expr_name(item.context_expr).lower()
                if ctx_name in ("atomic", "transaction.atomic", "django.db.transaction.atomic"):
                    is_atomic = True
                    break
                if isinstance(item.context_expr, ast.Call):
                    func_name = _expr_name(item.context_expr.func).lower()
                    if func_name in ("atomic", "transaction.atomic", "django.db.transaction.atomic"):
                        is_atomic = True
                        break

            if not is_atomic:
                continue

            for child in ast.walk(with_stmt):
                if not isinstance(child, ast.Call):
                    continue
                if not _is_task_dispatch(child) or id(child) in on_commit_calls:
                    continue
                if id(child) not in reported_dispatches:
                    reported_dispatches.add(id(child))
                    self._add(
                        "CG-022",
                        child,
                        node.name,
                        "Premature task dispatch inside Django transaction.atomic(): "
                        "if the transaction rolls back, the enqueued task will operate "
                        "on non-existent data (Transactional Outbox Race).",
                        "Wrap the task dispatch in transaction.on_commit(lambda: "
                        "my_task.delay(...)) to ensure it runs only after a successful commit.",
                    )

        # Also check if function has @transaction.atomic decorator
        is_func_atomic = any(
            _expr_name(dec.func if isinstance(dec, ast.Call) else dec).lower() in (
                "atomic", "transaction.atomic", "django.db.transaction.atomic"
            )
            for dec in node.decorator_list
        )
        if is_func_atomic:
            for dispatch in dispatches:
                if id(dispatch) not in reported_dispatches:
                    reported_dispatches.add(id(dispatch))
                    self._add(
                        "CG-022",
                        dispatch,
                        node.name,
                        "Premature task dispatch inside Django transaction.atomic(): "
                        "if the transaction rolls back, the enqueued task will operate "
                        "on non-existent data (Transactional Outbox Race).",
                        "Wrap the task dispatch in transaction.on_commit(lambda: "
                        "my_task.delay(...)) to ensure it runs only after a successful commit.",
                    )

    def _check_cg_023(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-023: Non-Idempotent Retryable Worker Task.

        Detect functions decorated with Celery/Dramatiq/ARQ retry semantics that perform
        state mutations + DB commit without idempotency guards.
        """
        is_retryable_task = False

        for dec in node.decorator_list:
            func = dec.func if isinstance(dec, ast.Call) else dec
            dec_expr = _expr_name(func).lower()

            # Celery / Dramatiq / ARQ decorators
            if any(
                k in dec_expr
                for k in ("task", "shared_task", "actor", "dramatiq")
            ):
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if kw.arg == "acks_late" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            is_retryable_task = True
                        if kw.arg in ("autoretry_for", "max_retries", "retry_backoff"):
                            is_retryable_task = True
                if "actor" in dec_expr:
                    is_retryable_task = True

        # Check for self.retry() calls in body
        for n in local_nodes:
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "retry"
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "self"
            ):
                is_retryable_task = True

        if not is_retryable_task:
            return

        # Check for state mutations + DB commit
        has_mutation = any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("commit", "save", "update", "add")
            for n in local_nodes
        ) or any(
            isinstance(n, (ast.Assign, ast.AugAssign))
            and (
                (isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Attribute))
                or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) for t in n.targets))
            )
            for n in local_nodes
        )

        has_commit = any(_is_commit_call(n) for n in local_nodes)

        if not (has_mutation and has_commit) or _has_repeatable_row_assignment(node):
            return

        # Check for idempotency guards (sanitizers)
        has_idempotency = False
        lock_spans = _get_lock_spans(node, custom_lock_names=self.custom_lock_names)
        if lock_spans:
            has_idempotency = True

        if not has_idempotency:
            for n in local_nodes:
                name = ""
                if isinstance(n, ast.Name):
                    name = n.id.lower()
                elif isinstance(n, ast.Attribute):
                    name = n.attr.lower()
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    name = n.func.attr.lower()
                    if name in ("with_for_update", "select_for_update"):
                        has_idempotency = True
                        break
                    if name in ("get_or_create", "update_or_create"):
                        has_idempotency = True
                        break

                if any(k in name for k in ("idempotency", "dedup", "lock", "advisory_lock")):
                    has_idempotency = True
                    break

        # Check for custom lock names from config
        if not has_idempotency and self.custom_lock_names:
            for n in local_nodes:
                expr_str = _expr_name(n).lower()
                if any(c_lock.lower() in expr_str for c_lock in self.custom_lock_names):
                    has_idempotency = True
                    break

        # Check for IntegrityError handling
        if not has_idempotency:
            for n in local_nodes:
                if isinstance(n, ast.Try) and _catches_integrity_error(n):
                    has_idempotency = True
                    break

        if not has_idempotency:
            self._add(
                "CG-023",
                node,
                node.name,
                "Non-idempotent retryable worker task: task configured with retries "
                "performs state mutations and DB commits without idempotency guards "
                "(row lock, deduplication key, or IntegrityError handling).",
                "Add a distributed lock (redis.lock), database row lock "
                "(.with_for_update()), idempotency key check, or IntegrityError "
                "handler to prevent duplicate side effects on task retry.",
            )

    def _check_cg_024(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]
    ) -> None:
        """Rule CG-024: External Network I/O Inside Open Database Transaction.

        Detect external HTTP/RPC calls inside active database transaction contexts
        (transaction.atomic(), session.begin(), or between with_for_update and commit).
        Holding DB row locks across unpredictable external network latency causes
        connection pool exhaustion and production deadlocks.
        """
        _HTTP_METHODS: frozenset[str] = frozenset({
            "get", "post", "put", "delete", "patch", "head", "options", "request",
        })

        def _is_network_call(call_node: ast.Call) -> bool:
            if isinstance(call_node.func, ast.Attribute):
                attr = call_node.func.attr.lower()
                caller = _expr_name(call_node.func.value).lower()
                if (
                    attr in _HTTP_METHODS
                    and any(
                        m in caller
                        for m in ("requests", "httpx", "aiohttp", "urllib", "client", "http", "api")
                    )
                    and not any(db_k in caller for db_k in ("db", "database", "sql"))
                ):
                    return True
                if "stripe" in caller or "stripe" in attr:
                    return True
                if "urlopen" in attr and "urllib" in caller:
                    return True
            elif isinstance(call_node.func, ast.Name):
                name = call_node.func.id.lower()
                if name in ("urlopen",):
                    return True
            return False

        def _is_db_transaction_context(ctx_expr: ast.AST) -> bool:
            name = _expr_name(ctx_expr.func if isinstance(ctx_expr, ast.Call) else ctx_expr).lower()
            return any(
                k in name
                for k in ("atomic", "transaction.atomic", "session.begin", ".begin")
            )

        reported_calls: set[int] = set()

        for with_stmt in (n for n in local_nodes if isinstance(n, (ast.With, ast.AsyncWith))):
            is_tx = False
            for item in with_stmt.items:
                if _is_db_transaction_context(item.context_expr):
                    is_tx = True
                    break
            if not is_tx:
                continue

            for child in ast.walk(with_stmt):
                if (
                    isinstance(child, ast.Call)
                    and _is_network_call(child)
                    and id(child) not in reported_calls
                ):
                    reported_calls.add(id(child))
                    self._add(
                        "CG-024",
                        child,
                        node.name,
                        "External network I/O inside open database transaction: HTTP/RPC "
                        "call executed while holding database row locks or inside "
                        "transaction.atomic()/session.begin() causes connection pool "
                        "exhaustion and production deadlocks under network latency.",
                        "Move the external HTTP/RPC call outside the database transaction "
                        "scope, or use a two-phase commit / transactional outbox pattern.",
                    )

        # Also check between with_for_update() and commit()
        locked_query_lines: list[int] = []
        for n in local_nodes:
            if isinstance(n, ast.Call):
                func_expr = _expr_name(n.func).lower()
                if "with_for_update" in func_expr or "select_for_update" in func_expr:
                    locked_query_lines.append(getattr(n, "lineno", 0))

        commit_lines = [getattr(n, "lineno", 0) for n in local_nodes if _is_commit_call(n)]

        if locked_query_lines and commit_lines:
            q_line = min(locked_query_lines)
            c_line = max(commit_lines)
            if q_line < c_line:
                for n in local_nodes:
                    if isinstance(n, ast.Call) and _is_network_call(n):
                        call_line = getattr(n, "lineno", 0)
                        if q_line < call_line < c_line and id(n) not in reported_calls:
                            reported_calls.add(id(n))
                            self._add(
                                "CG-024",
                                n,
                                node.name,
                                "External network I/O inside open database transaction: HTTP/RPC "
                                "call executed while holding database row locks or inside "
                                "transaction.atomic()/session.begin() causes connection pool "
                                "exhaustion and production deadlocks under network latency.",
                                "Move the external HTTP/RPC call outside the database transaction "
                                "scope, or use a two-phase commit / transactional outbox pattern.",
                            )

    def _check_cg_025(self, node: ast.AsyncFunctionDef, local_nodes: list[ast.AST]) -> None:
        """Rule CG-025: Blocking Call Inside async def (Event-Loop Starvation).

        Flags synchronous blocking calls (time.sleep, requests.*, urllib.request.urlopen,
        subprocess.*) inside async coroutines.
        Sanitized if wrapped in asyncio.to_thread(), loop.run_in_executor(), or anyio.to_thread.run_sync().
        """
        sanitized_ids: set[int] = set()
        for n in local_nodes:
            if isinstance(n, ast.Call):
                cname = _expr_name(n.func).lower()
                if any(k in cname for k in ("to_thread", "run_in_executor", "run_sync")):
                    for child in ast.walk(n):
                        sanitized_ids.add(id(child))

        reported_lines: set[int] = set()
        for n in local_nodes:
            if not isinstance(n, ast.Call):
                continue
            if id(n) in sanitized_ids:
                continue

            call_expr = _expr_name(n.func)
            call_lower = call_expr.lower()

            is_blocking = False
            hint = ""

            # Pattern A: time.sleep() or bare sleep()
            if call_lower == "time.sleep" or (isinstance(n.func, ast.Name) and n.func.id == "sleep"):
                is_blocking = True
                hint = (
                    "Replace 'time.sleep(...)' with 'await asyncio.sleep(...)' to yield control "
                    "back to the event loop."
                )

            # Pattern B: requests.*()
            elif call_lower.startswith("requests.") and any(
                m in call_lower for m in ("get", "post", "put", "delete", "patch", "request", "head", "options")
            ):
                is_blocking = True
                hint = (
                    f"Replace synchronous HTTP client '{call_expr}' with an async client "
                    "(e.g., httpx or aiohttp), or offload the call using 'await asyncio.to_thread(...)''."
                )

            # Pattern C: urllib.request.urlopen() or urllib.request.*
            elif call_lower in ("urllib.request.urlopen", "urlopen") or (
                call_lower.startswith("urllib.request.") and "urlopen" in call_lower
            ):
                is_blocking = True
                hint = (
                    f"Replace synchronous '{call_expr}' with an async HTTP client "
                    "or offload the call using 'await asyncio.to_thread(...)''."
                )

            # Pattern D: subprocess.*()
            elif call_lower.startswith("subprocess.") and any(
                m in call_lower for m in ("run", "call", "check_output", "check_call", "popen")
            ):
                is_blocking = True
                hint = (
                    f"Use 'await asyncio.create_subprocess_exec(...)' or offload synchronous "
                    f"'{call_expr}' using 'await asyncio.to_thread(...)''."
                )

            if is_blocking:
                lineno = getattr(n, "lineno", node.lineno)
                if lineno not in reported_lines:
                    reported_lines.add(lineno)
                    self._add(
                        "CG-025",
                        n,
                        node.name,
                        f"Blocking synchronous call '{call_expr}' inside async function '{node.name}' "
                        "blocks the event loop thread, starving all concurrent tasks and degrading throughput.",
                        hint,
                    )

    def _check_cg_026(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]) -> None:
        """Rule CG-026: Unreferenced / Orphan Asyncio Background Task (Fire-and-Forget Task Race).

        Flags bare expression calls to asyncio.create_task() or loop.create_task()
        without assigning, returning, awaiting, or passing the task to a collection.
        """
        for stmt in local_nodes:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                call_name = _expr_name(call.func).lower()
                if (
                    call_name == "asyncio.create_task"
                    or call_name.endswith(".create_task")
                    or (isinstance(call.func, ast.Name) and call.func.id == "create_task")
                ):
                    self._add(
                        "CG-026",
                        call,
                        node.name,
                        f"Unreferenced / orphan asyncio task: '{_expr_name(call.func)}' is invoked as a bare "
                        "expression without retaining a strong reference. The Python runtime garbage collector "
                        "may destroy the task mid-execution, silently dropping unfinished work.",
                        "Save the task reference to a variable, return it, or store it in a background tasks collection "
                        "(e.g., 'tasks.add(asyncio.create_task(...))') to prevent premature garbage collection.",
                    )

    def _check_cg_027(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], local_nodes: list[ast.AST]) -> None:
        """Rule CG-027: Non-Atomic Redis Check-Then-Set Race (Distributed Cache Race).

        Flags Redis get() followed by a conditional if check and a Redis set() without
        nx=True, xx=True, a transaction pipeline, or a distributed lock.
        """
        lock_spans = _get_lock_spans(node, self.custom_lock_names)
        pipeline_spans: list[tuple[int, int]] = []
        for with_stmt in (n for n in local_nodes if isinstance(n, (ast.With, ast.AsyncWith))):
            for item in with_stmt.items:
                ctx_name = _expr_name(item.context_expr).lower()
                if any(k in ctx_name for k in ("pipeline", "multi", "transaction", "lock", "redlock")):
                    pipeline_spans.append((with_stmt.lineno, getattr(with_stmt, "end_lineno", with_stmt.lineno)))

        all_safe_spans = lock_spans + pipeline_spans

        def _is_span_protected(lineno: int) -> bool:
            return any(start <= lineno <= end for start, end in all_safe_spans)

        redis_receivers = {
            _expr_name(n.target) for n in local_nodes
            if isinstance(n, ast.AnnAssign) and "redis" in _expr_name(n.annotation).lower()
        }
        for assignment in local_nodes:
            if isinstance(assignment, ast.Assign) and isinstance(assignment.value, ast.Call):
                factory = _expr_name(assignment.value.func).lower().split(".")
                if any(part in {"redis", "strictredis"} for part in factory):
                    redis_receivers.update(_expr_name(t) for t in assignment.targets)

        def _redis_receiver(call: ast.Call) -> str:
            if not isinstance(call.func, ast.Attribute):
                return ""
            base = _expr_name(call.func.value)
            tokens = base.lower().replace("_", ".").split(".")
            return base if "redis" in tokens or base in redis_receivers else ""

        def _is_redis_get(call: ast.Call) -> bool:
            return isinstance(call.func, ast.Attribute) and call.func.attr == "get" and bool(_redis_receiver(call))

        def _is_redis_set(call: ast.Call) -> bool:
            return (isinstance(call.func, ast.Attribute)
                    and call.func.attr in {"set", "setex", "setrange", "mset"}
                    and bool(_redis_receiver(call)))

        def _has_atomic_flag(call: ast.Call) -> bool:
            for kw in call.keywords:
                if kw.arg in ("nx", "xx"):
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return True
                    if isinstance(kw.value, ast.Name) and kw.value.id == "True":
                        return True
            return False

        redis_gets: list[ast.Call] = []
        for n in local_nodes:
            if isinstance(n, ast.Call) and _is_redis_get(n):
                line = getattr(n, "lineno", 0)
                if not _is_span_protected(line):
                    redis_gets.append(n)

        if not redis_gets:
            return

        reported_sets: set[int] = set()

        for get_call in redis_gets:
            get_line = getattr(get_call, "lineno", 0)
            for if_node in (n for n in local_nodes if isinstance(n, ast.If)):
                if if_node.lineno >= get_line:
                    for child in ast.walk(if_node):
                        if (isinstance(child, ast.Call) and _is_redis_set(child)
                                and _redis_receiver(child) == _redis_receiver(get_call)):
                            if (get_call.args and child.args
                                    and ast.dump(get_call.args[0]) != ast.dump(child.args[0])):
                                continue
                            set_line = getattr(child, "lineno", 0)
                            if set_line < get_line:
                                continue
                            if id(child) in reported_sets:
                                continue
                            if _is_span_protected(set_line):
                                continue
                            if _has_atomic_flag(child):
                                continue

                            reported_sets.add(id(child))
                            self._add(
                                "CG-027",
                                child,
                                node.name,
                                f"Non-atomic Redis Check-Then-Set race: Redis get operation at line {get_line} "
                                f"followed by conditional set at line {set_line} without atomic guards (nx=True), "
                                "a transaction pipeline, or a distributed lock allows concurrent workers to overwrite state.",
                                "Use atomic Redis operations such as 'redis.set(..., nx=True)', a Redis transaction "
                                "pipeline ('pipeline()'), or a distributed lock ('redis.lock(...)') to ensure atomic check-and-set.",
                            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect sync function definitions for rule CG-005."""
        saved_aliases, saved_context = self.aliases, self.context_stack
        self.aliases, self.context_stack = {}, []
        try:
            local_nodes = list(_walk_local_nodes(node, include_self=False))
            self._check_cg_001(node, local_nodes)
            self._check_cg_005(node, local_nodes)
            self._check_cg_016(node, local_nodes)
            self._check_cg_017(node, local_nodes)
            self._check_cg_018(node, local_nodes)
            self._check_cg_019(node, local_nodes)
            self._check_cg_020(node, local_nodes)
            self._check_cg_021(node, local_nodes)
            self._check_cg_022(node, local_nodes)
            self._check_cg_023(node, local_nodes)
            self._check_cg_024(node, local_nodes)
            self._check_cg_026(node, local_nodes)
            self._check_cg_027(node, local_nodes)
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
            self._check_cg_022(node, local_nodes)
            self._check_cg_023(node, local_nodes)
            self._check_cg_024(node, local_nodes)
            self._check_cg_025(node, local_nodes)
            self._check_cg_026(node, local_nodes)
            self._check_cg_027(node, local_nodes)
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


ASTRuleVisitor = ConcurrencyASTVisitor


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
    source_code: str,
    filename: str = "<memory>",
    custom_rules: Optional[list[dict[str, Any]]] = None,
    config: Optional[Any] = None,
    custom_lock_names: Optional[Union[list[str], set[str]]] = None,
    project_graph: Optional[Any] = None,
    tree: Optional[ast.AST] = None,
) -> list[ASTFinding]:
    """Scan Python source code string for concurrency vulnerabilities."""
    parsed_tree = tree if tree is not None else ast.parse(source_code, filename=filename)
    visitor = ConcurrencyASTVisitor(
        filename=filename,
        tree=parsed_tree,
        config=config,
        custom_lock_names=custom_lock_names,
        project_graph=project_graph,
    )
    visitor.visit(parsed_tree)
    if isinstance(parsed_tree, ast.Module):
        for site, function, resource in shared_writes(parsed_tree):
            visitor._add("CG-030", site, function, f"Shared state '{resource}' read before await and mutated afterward.",
                         "Protect the read, await and mutation with one shared async lock.")
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
    raw_findings = visitor.findings + taint_findings + (_custom_rule_findings(parsed_tree, filename, custom_rules) if custom_rules else [])
    if config is not None and hasattr(config, "is_rule_enabled"):
        return [f for f in raw_findings if config.is_rule_enabled(f.rule_id, file_path=filename)]
    return raw_findings


def discover_python_files(path: Path, config: Optional[Any] = None) -> list[Path]:
    """Discover Python files in a directory or file, skipping hidden and excluded folders."""
    if not path.is_dir():
        if config is not None and hasattr(config, "is_path_excluded") and config.is_path_excluded(path):
            return []
        return [path]

    py_files: list[Path] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and d not in EXCLUDED_DIRS
            and not (config is not None and hasattr(config, "is_path_excluded") and config.is_path_excluded(Path(root) / d, root_dir=path))
        ]
        for f in sorted(files):
            if f.endswith(".py"):
                fpath = Path(root) / f
                if config is not None and hasattr(config, "is_path_excluded") and config.is_path_excluded(fpath, root_dir=path):
                    continue
                py_files.append(fpath)
    return sorted(py_files)


def scan_file(
    file_path: Path,
    custom_rules: Optional[list[dict[str, Any]]] = None,
    cache_manager: Optional[Any] = None,
    suppression_filter: Optional[SuppressionFilter] = None,
    config: Optional[Any] = None,
    project_graph: Optional[Any] = None,
    parsed_module: Optional[Any] = None,
) -> list[ASTFinding]:
    """Scan a Python file for concurrency vulnerabilities, skipping unparseable files."""
    dep_digest = project_graph.get_dependency_digest(file_path) if project_graph is not None else None
    if cache_manager is not None:
        cached: Optional[list[ASTFinding]] = None
        if hasattr(cache_manager, "get"):
            try:
                cached = cache_manager.get(file_path, dependency_digest=dep_digest)
            except TypeError:
                cached = cache_manager.get(file_path)
        elif hasattr(cache_manager, "get_cached_findings"):
            try:
                raw_cached = cache_manager.get_cached_findings(file_path, dependency_digest=dep_digest)
            except TypeError:
                raw_cached = cache_manager.get_cached_findings(file_path)
            if raw_cached is not None:
                from concurrency_guard.cache.manager import dict_to_finding

                cached = [dict_to_finding(d) for d in raw_cached]

        if cached is not None:
            filtered = suppression_filter.filter_findings(cached, file_path=file_path) if suppression_filter is not None else SuppressionFilter().filter_findings(cached, file_path=file_path)
            if config is not None and hasattr(config, "is_rule_enabled"):
                return [f for f in filtered if config.is_rule_enabled(f.rule_id, file_path=file_path)]
            return filtered

    parsed_tree: Optional[ast.AST] = None
    if parsed_module is not None:
        if hasattr(parsed_module, "source") and hasattr(parsed_module, "tree"):
            source_code = parsed_module.source
            parsed_tree = parsed_module.tree
        elif isinstance(parsed_module, tuple) and len(parsed_module) == 2:
            parsed_tree, source_code = parsed_module
        else:
            try:
                source_code = file_path.read_text(encoding="utf-8-sig")
            except (UnicodeDecodeError, OSError):
                return []
    else:
        try:
            source_code = file_path.read_text(encoding="utf-8-sig")
        except (UnicodeDecodeError, OSError):
            return []

    try:
        findings = scan_source_code(
            source_code,
            filename=str(file_path),
            custom_rules=custom_rules,
            config=config,
            project_graph=project_graph,
            tree=parsed_tree,
        )
    except (SyntaxError, ValueError):
        findings = []

    filter_obj = suppression_filter or SuppressionFilter()
    filter_obj.parse_source(source_code, filepath=file_path)
    final_findings = filter_obj.filter_findings(findings, file_path=file_path)
    if config is not None and hasattr(config, "is_rule_enabled"):
        final_findings = [f for f in final_findings if config.is_rule_enabled(f.rule_id, file_path=file_path)]

    if cache_manager is not None:
        if hasattr(cache_manager, "set"):
            try:
                cache_manager.set(file_path, final_findings, dependency_digest=dep_digest)
            except TypeError:
                cache_manager.set(file_path, final_findings)
        elif hasattr(cache_manager, "update_cache"):
            from concurrency_guard.cache.manager import finding_to_dict

            try:
                cache_manager.update_cache(
                    file_path, [finding_to_dict(f) for f in findings], dependency_digest=dep_digest
                )
            except TypeError:
                cache_manager.update_cache(file_path, [finding_to_dict(f) for f in findings])

    return final_findings


def sort_findings(findings: list[ASTFinding]) -> list[ASTFinding]:
    """Sort findings deterministically by (filename, lineno, rule_id, col_offset)."""
    return sorted(
        dict.fromkeys(findings),
        key=lambda f: (
            str(f.filename),
            f.lineno,
            f.rule_id,
            getattr(f, "col_offset", 0) or 0,
        ),
    )


def _scan_worker_task(
    file_path: Path,
    custom_rules: Optional[list[dict[str, Any]]],
    ignore_pragma: bool,
    config: Optional[Any] = None,
    project_graph: Optional[Any] = None,
) -> tuple[Path, list[ASTFinding]]:
    """Isolated, picklable worker task for parallel execution."""
    suppression = SuppressionFilter(ignore_pragma=ignore_pragma)
    findings = scan_file(
        file_path,
        custom_rules=custom_rules,
        suppression_filter=suppression,
        config=config,
        project_graph=project_graph,
    )
    return file_path, findings


def scan_directory(
    dir_path: Path,
    custom_rules: Optional[list[dict[str, Any]]] = None,
    cache_manager: Optional[Any] = None,
    suppression_filter: Optional[SuppressionFilter] = None,
    workers: Optional[int] = None,
    jobs: Optional[int] = None,
    config: Optional[Any] = None,
    cross_file: bool = True,
) -> list[ASTFinding]:
    """Scan a directory recursively, including cross-file call-chain analysis."""
    from concurrency_guard.engine import scan_directory_parallel

    return scan_directory_parallel(
        dir_path=dir_path,
        custom_rules=custom_rules,
        cache_manager=cache_manager,
        suppression_filter=suppression_filter,
        workers=workers,
        jobs=jobs,
        config=config,
        cross_file=cross_file,
    )


def scan_project(
    file_paths: list[Path],
    roots: Optional[list[Path]] = None,
    custom_rules: Optional[list[dict[str, Any]]] = None,
    cache_manager: Optional[Any] = None,
    suppression_filter: Optional[SuppressionFilter] = None,
    workers: Optional[int] = None,
    jobs: Optional[int] = None,
    config: Optional[Any] = None,
    cross_file: bool = True,
    parsed_modules: Optional[dict[Path, Any]] = None,
) -> list[ASTFinding]:
    """Scan files and propagate shared-state hazards to transitive callers."""
    from concurrency_guard.engine import scan_project_parallel

    return scan_project_parallel(
        file_paths=file_paths,
        roots=roots,
        custom_rules=custom_rules,
        cache_manager=cache_manager,
        suppression_filter=suppression_filter,
        workers=workers,
        jobs=jobs,
        config=config,
        cross_file=cross_file,
        parsed_modules=parsed_modules,
    )

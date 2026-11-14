"""Project-wide, import-aware call graph construction.

This module deliberately resolves only source files supplied to the scanner. It
never imports user code, so building the graph is safe and deterministic.
"""

from __future__ import annotations

import ast
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union


@dataclass(frozen=True)
class FunctionNode:
    """A source function identified by its module-qualified name."""

    qualified_name: str
    filename: str
    lineno: int
    name: str
    is_async: bool


@dataclass(frozen=True)
class CallSite:
    """A resolved local call and the simple argument names supplied to it."""

    source: str
    target: str
    lineno: int
    arguments: tuple[str, ...]
    keywords: tuple[tuple[str, str], ...] = ()


@dataclass
class CallGraph:
    """Directed call graph and local metadata for a scanned source project."""

    functions: dict[str, FunctionNode] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    reverse_edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    shared_mutations: set[str] = field(default_factory=set)
    call_sites: list[CallSite] = field(default_factory=list)

    def callers_of(self, qualified_name: str) -> set[str]:
        """Return every transitive caller of a function."""
        callers: set[str] = set()
        pending = deque(self.reverse_edges.get(qualified_name, set()))
        while pending:
            caller = pending.popleft()
            if caller not in callers:
                callers.add(caller)
                pending.extend(self.reverse_edges.get(caller, set()))
        return callers


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _module_name(path: Path, roots: list[Path]) -> str:
    """Use the nearest supplied root as a stable Python-ish module name."""
    resolved_path = path.resolve()
    resolved_roots = [candidate.resolve() for candidate in roots]
    root = max((candidate for candidate in resolved_roots if candidate == resolved_path.parent or candidate in resolved_path.parents), key=lambda p: len(p.parts), default=None)
    if root is None:
        return resolved_path.stem
    relative = resolved_path.relative_to(root).with_suffix("")
    parts = relative.parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _module_aliases(tree: ast.Module, module: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    package = module.rsplit(".", 1)[0] if "." in module else ""
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for imported in statement.names:
                aliases[imported.asname or imported.name.split(".")[0]] = imported.name
        elif isinstance(statement, ast.ImportFrom):
            base = statement.module or ""
            if statement.level:
                parent_parts = package.split(".") if package else []
                base = ".".join(parent_parts[: max(0, len(parent_parts) - statement.level + 1)] + ([base] if base else []))
            for imported in statement.names:
                if imported.name != "*":
                    aliases[imported.asname or imported.name] = f"{base}.{imported.name}".strip(".")
    return aliases


def _shared_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and isinstance(statement.value, (ast.List, ast.Dict, ast.Set)):
            names.update(target.id for target in statement.targets if isinstance(target, ast.Name))
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.value, (ast.List, ast.Dict, ast.Set)) and isinstance(statement.target, ast.Name):
            names.add(statement.target.id)
    return names


def _mutates_shared(function: Union[ast.FunctionDef, ast.AsyncFunctionDef], shared: set[str]) -> bool:
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                root = target.value.id if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) else getattr(target, "id", "")
                if root in shared:
                    return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in shared
            and node.func.attr in {"append", "extend", "update", "pop", "remove", "clear", "setdefault"}
        ):
            return True
    return False


def build_call_graph(files: list[Path], roots: Optional[list[Path]] = None) -> CallGraph:
    """Build a graph for local calls and imports among ``files``.

    Calls that resolve to third-party packages are intentionally omitted. A
    malformed source file is skipped just like the regular scanner.
    """
    roots = roots or [Path(os.path.commonpath([str(path.parent) for path in files]))] if files else []
    parsed: list[tuple[Path, str, ast.Module]] = []
    for path in files:
        try:
            parsed.append((path, _module_name(path, roots), ast.parse(path.read_text(encoding="utf-8"), filename=str(path))))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

    graph = CallGraph()
    aliases_by_module: dict[str, dict[str, str]] = {}
    # Index module functions and class methods under stable Class.method names.
    for path, module, tree in parsed:
        aliases_by_module[module] = _module_aliases(tree, module)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = f"{module}.{node.name}".strip(".")
                graph.functions[qualified] = FunctionNode(qualified, str(path), node.lineno, node.name, isinstance(node, ast.AsyncFunctionDef))
                if _mutates_shared(node, _shared_names(tree)):
                    graph.shared_mutations.add(qualified)
            elif isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qualified = f"{module}.{node.name}.{method.name}".strip(".")
                        graph.functions[qualified] = FunctionNode(qualified, str(path), method.lineno, method.name, isinstance(method, ast.AsyncFunctionDef))
                        if _mutates_shared(method, _shared_names(tree)):
                            graph.shared_mutations.add(qualified)

    for _, module, tree in parsed:
        aliases = aliases_by_module[module]
        functions: list[tuple[Union[ast.FunctionDef, ast.AsyncFunctionDef], str, dict[str, str]]] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append((node, f"{module}.{node.name}".strip("."), {}))
            elif isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        annotations: dict[str, str] = {}
                        for arg in method.args.args + method.args.kwonlyargs:
                            if arg.annotation is not None:
                                annotations[arg.arg] = _dotted_name(arg.annotation).split(".")[-1]
                        functions.append((method, f"{module}.{node.name}.{method.name}".strip("."), annotations))
        for function, source, annotations in functions:
            for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
                name = _dotted_name(call.func)
                first, _, suffix = name.partition(".")
                resolved = f"{aliases[first]}.{suffix}" if first in aliases and suffix else aliases.get(first, name)
                owner = source.rsplit(".", 1)[0]
                candidates: tuple[str, ...] = (resolved, f"{module}.{name}".strip("."))
                if first in {"self", "cls"} and suffix:
                    candidates += (f"{owner}.{suffix}",)
                if first in annotations and suffix:
                    candidates += (f"{module}.{annotations[first]}.{suffix}",)
                for candidate in candidates:
                    if candidate in graph.functions:
                        graph.edges[source].add(candidate)
                        graph.reverse_edges[candidate].add(source)
                        graph.call_sites.append(
                            CallSite(
                                source=source,
                                target=candidate,
                                lineno=call.lineno,
                                arguments=tuple(_dotted_name(argument).split(".")[0] for argument in call.args),
                                keywords=tuple((keyword.arg, _dotted_name(keyword.value).split(".")[0]) for keyword in call.keywords if keyword.arg is not None),
                            )
                        )
    return graph


@dataclass
class FunctionSummary:
    """Pre-analysis summary for a module-level local function."""

    name: str
    is_async: bool
    returns_unlocked_entity: bool = False
    returns_locked_entity: bool = False
    mutated_param_indices: set[int] = field(default_factory=set)
    mutated_param_names: set[str] = field(default_factory=set)
    performs_commit: bool = False
    acquires_lock_context: bool = False


def _is_ast_query_call(node: ast.AST) -> bool:
    """Check if AST node represents an ORM read query."""
    if not isinstance(node, ast.Call):
        return False
    name = _dotted_name(node.func)
    if "select" in name:
        return True
    return bool(any(name.endswith(suffix) for suffix in (".get", ".scalar", ".scalars", ".first", ".one", ".one_or_none", ".all", ".execute")))


def _has_ast_query_lock(node: ast.AST) -> bool:
    """Check if AST node contains .with_for_update() or .select_for_update()."""
    return any(
        isinstance(c, ast.Attribute) and c.attr in ("with_for_update", "select_for_update")
        for c in ast.walk(node)
    )


def _is_ast_commit_call(node: ast.AST) -> bool:
    """Check if AST node represents a database commit or save."""
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in ("commit", "flush", "save", "asave")
    return False


def _has_ast_lock_context(
    with_node: Union[ast.With, ast.AsyncWith],
    custom_lock_names: Optional[Union[list[str], set[str]]] = None,
) -> bool:
    """Check if a with/async with block manages a concurrency lock or transaction."""
    for item in with_node.items:
        expr_str = _dotted_name(item.context_expr).lower()
        if custom_lock_names and any(cl.lower() in expr_str for cl in custom_lock_names):
            return True
        if any(term in expr_str for term in ("lock", "advisory", "redis", "mutex", "atomic", "semaphore")):
            return True
        for child in ast.walk(item.context_expr):
            if isinstance(child, ast.Name):
                cid = child.id.lower()
                if custom_lock_names and any(cl.lower() in cid for cl in custom_lock_names):
                    return True
                if any(term in cid for term in ("lock", "mutex")):
                    return True
            if isinstance(child, ast.Attribute):
                cattr = child.attr.lower()
                if custom_lock_names and any(cl.lower() in cattr for cl in custom_lock_names):
                    return True
                if any(term in cattr for term in ("lock", "atomic")):
                    return True
    return False


def _extract_target_root_name(target: ast.AST) -> str:
    """Extract root identifier name from an assignment target (e.g. user.balance -> user)."""
    curr = target
    while isinstance(curr, (ast.Attribute, ast.Subscript)):
        curr = curr.value
    if isinstance(curr, ast.Name):
        return curr.id
    return ""


def analyze_module_functions(
    tree: ast.Module,
    custom_lock_names: Optional[Union[list[str], set[str]]] = None,
) -> dict[str, FunctionSummary]:
    """Perform a fast, cycle-safe module-level function summary pass over all functions."""
    summaries: dict[str, FunctionSummary] = {}
    function_nodes: dict[str, Union[ast.FunctionDef, ast.AsyncFunctionDef]] = {}
    local_calls_by_func: dict[str, list[ast.Call]] = defaultdict(list)

    # 1. Collect all local top-level and class methods
    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_nodes[item.name] = item
        elif isinstance(item, ast.ClassDef):
            for method in item.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    function_nodes[method.name] = method

    # 2. Compute base summary for each function
    for func_name, func_node in function_nodes.items():
        is_async = isinstance(func_node, ast.AsyncFunctionDef)
        summary = FunctionSummary(name=func_name, is_async=is_async)

        # Check decorators for @transaction.atomic or lock decorators
        for dec in func_node.decorator_list:
            dec_name = _dotted_name(dec).lower()
            if custom_lock_names and any(cl.lower() in dec_name for cl in custom_lock_names):
                summary.acquires_lock_context = True
            if "atomic" in dec_name or "lock" in dec_name:
                summary.acquires_lock_context = True

        # Map function parameters
        param_names: list[str] = [arg.arg for arg in func_node.args.args]
        param_to_idx: dict[str, int] = {arg.arg: idx for idx, arg in enumerate(func_node.args.args)}
        for kw_arg in func_node.args.kwonlyargs:
            param_names.append(kw_arg.arg)
            param_to_idx[kw_arg.arg] = len(param_names) - 1

        # Track parameter aliases inside function: alias -> param_name
        param_aliases: dict[str, str] = {p: p for p in param_names}

        # Track local variable query sources: var_name -> (is_query, is_locked)
        var_query_sources: dict[str, tuple[bool, bool]] = {}

        # Scan function body for statements
        for node in ast.walk(func_node):
            # Record local helper calls
            if isinstance(node, ast.Call):
                call_name = _dotted_name(node.func)
                if call_name in function_nodes:
                    local_calls_by_func[func_name].append(node)

            # Check commits
            if _is_ast_commit_call(node):
                summary.performs_commit = True

            # Check lock contexts
            if isinstance(node, (ast.With, ast.AsyncWith)) and _has_ast_lock_context(node, custom_lock_names=custom_lock_names):
                summary.acquires_lock_context = True

            # Track variable assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        val = node.value.value if isinstance(node.value, ast.Await) else node.value
                        if isinstance(val, ast.Name) and val.id in param_aliases:
                            param_aliases[target.id] = param_aliases[val.id]
                        if _is_ast_query_call(val):
                            has_lock = _has_ast_query_lock(val)
                            var_query_sources[target.id] = (True, has_lock)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None and isinstance(node.target, ast.Name):
                val = node.value.value if isinstance(node.value, ast.Await) else node.value
                if isinstance(val, ast.Name) and val.id in param_aliases:
                    param_aliases[node.target.id] = param_aliases[val.id]
                if _is_ast_query_call(val):
                    has_lock = _has_ast_query_lock(val)
                    var_query_sources[node.target.id] = (True, has_lock)

            # Check parameter mutations (AugAssign: user.balance -= 50)
            if isinstance(node, ast.AugAssign):
                root = _extract_target_root_name(node.target)
                if root in param_aliases:
                    param = param_aliases[root]
                    summary.mutated_param_names.add(param)
                    if param in param_to_idx:
                        summary.mutated_param_indices.add(param_to_idx[param])

            # Check parameter mutations (Assign: user.balance = ..., user.status = ...)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, (ast.Attribute, ast.Subscript)):
                        root = _extract_target_root_name(target)
                        if root in param_aliases:
                            param = param_aliases[root]
                            summary.mutated_param_names.add(param)
                            if param in param_to_idx:
                                summary.mutated_param_indices.add(param_to_idx[param])

            # Check mutating method calls: user.tags.append(...)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr in {
                    "append", "extend", "update", "pop", "remove", "clear", "setdefault", "add"
                }:
                    root = _extract_target_root_name(call.func.value)
                    if root in param_aliases:
                        param = param_aliases[root]
                        summary.mutated_param_names.add(param)
                        if param in param_to_idx:
                            summary.mutated_param_indices.add(param_to_idx[param])

            # Check return statements
            if isinstance(node, ast.Return) and node.value is not None:
                ret_val = node.value.value if isinstance(node.value, ast.Await) else node.value
                if _is_ast_query_call(ret_val):
                    if _has_ast_query_lock(ret_val):
                        summary.returns_locked_entity = True
                    else:
                        summary.returns_unlocked_entity = True
                elif isinstance(ret_val, ast.Name) and ret_val.id in var_query_sources:
                    is_q, has_lock = var_query_sources[ret_val.id]
                    if is_q:
                        if has_lock:
                            summary.returns_locked_entity = True
                        else:
                            summary.returns_unlocked_entity = True

        summaries[func_name] = summary

    # 3. Transitive Fixed-Point Propagation (max 3 iterations, cycle-safe)
    for _ in range(3):
        changed = False
        for func_name, summary in summaries.items():
            func_node = function_nodes[func_name]
            param_to_idx = {arg.arg: idx for idx, arg in enumerate(func_node.args.args)}

            for call in local_calls_by_func.get(func_name, []):
                callee_name = _dotted_name(call.func)
                callee_summary = summaries.get(callee_name)
                if callee_summary is None:
                    continue

                # Propagate commit delegation
                if callee_summary.performs_commit and not summary.performs_commit:
                    summary.performs_commit = True
                    changed = True

                # Propagate lock context
                if callee_summary.acquires_lock_context and not summary.acquires_lock_context:
                    summary.acquires_lock_context = True
                    changed = True

                # Propagate parameter mutation through helper argument passing
                for arg_idx, arg in enumerate(call.args):
                    if isinstance(arg, ast.Name) and arg.id in param_to_idx and arg_idx in callee_summary.mutated_param_indices:
                        caller_idx = param_to_idx[arg.id]
                        if caller_idx not in summary.mutated_param_indices:
                            summary.mutated_param_indices.add(caller_idx)
                            summary.mutated_param_names.add(arg.id)
                            changed = True

                # Check keyword arguments for parameter mutation
                for kw in call.keywords:
                    if kw.arg and isinstance(kw.value, ast.Name) and kw.value.id in param_to_idx and kw.arg in callee_summary.mutated_param_names:
                        caller_idx = param_to_idx[kw.value.id]
                        if caller_idx not in summary.mutated_param_indices:
                            summary.mutated_param_indices.add(caller_idx)
                            summary.mutated_param_names.add(kw.value.id)
                            changed = True

            # Propagate return values if returning local helper call
            for ret_node in (n for n in ast.walk(func_node) if isinstance(n, ast.Return)):
                if ret_node.value is not None:
                    val = ret_node.value.value if isinstance(ret_node.value, ast.Await) else ret_node.value
                    if isinstance(val, ast.Call):
                        callee = _dotted_name(val.func)
                        if callee in summaries:
                            callee_sum = summaries[callee]
                            if callee_sum.returns_locked_entity and not summary.returns_locked_entity:
                                summary.returns_locked_entity = True
                                changed = True
                            if callee_sum.returns_unlocked_entity and not summary.returns_unlocked_entity:
                                summary.returns_unlocked_entity = True
                                changed = True

        if not changed:
            break

    return summaries


def build_module_function_summaries(
    source_code_or_tree: Union[str, ast.Module],
    custom_lock_names: Optional[Union[list[str], set[str]]] = None,
) -> dict[str, FunctionSummary]:
    """Helper to parse source code or use existing AST to generate function summaries."""
    if isinstance(source_code_or_tree, str):
        try:
            tree = ast.parse(source_code_or_tree)
        except (SyntaxError, ValueError):
            return {}
    else:
        tree = source_code_or_tree
    return analyze_module_functions(tree, custom_lock_names=custom_lock_names)


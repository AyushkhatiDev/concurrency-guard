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
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _module_name(path: Path, roots: list[Path]) -> str:
    """Use the nearest supplied root as a stable Python-ish module name."""
    root = max((candidate for candidate in roots if candidate in path.parents), key=lambda p: len(p.parts))
    relative = path.relative_to(root).with_suffix("")
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


def _mutates_shared(function: ast.FunctionDef | ast.AsyncFunctionDef, shared: set[str]) -> bool:
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


def build_call_graph(files: list[Path], roots: list[Path] | None = None) -> CallGraph:
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
    for path, module, tree in parsed:
        aliases_by_module[module] = _module_aliases(tree, module)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = f"{module}.{node.name}".strip(".")
                graph.functions[qualified] = FunctionNode(qualified, str(path), node.lineno, node.name, isinstance(node, ast.AsyncFunctionDef))
                if _mutates_shared(node, _shared_names(tree)):
                    graph.shared_mutations.add(qualified)

    for _, module, tree in parsed:
        aliases = aliases_by_module[module]
        for function in (node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            source = f"{module}.{function.name}".strip(".")
            for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
                name = _dotted_name(call.func)
                first, _, suffix = name.partition(".")
                resolved = f"{aliases[first]}.{suffix}" if first in aliases and suffix else aliases.get(first, name)
                candidates = (resolved, f"{module}.{name}".strip("."))
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
                            )
                        )
    return graph

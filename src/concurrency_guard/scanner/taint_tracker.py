"""Forward data-flow tracking for shared-state references.

The tracker parses source only. It uses the project call graph to transfer
taint from a caller argument to its resolved local callee parameter, then runs
an intra-procedural forward flow over each function body.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from concurrency_guard.scanner.call_graph import CallGraph, FunctionNode

_MUTATORS = frozenset({
    "add",
    "append",
    "clear",
    "decr",
    "delete",
    "extend",
    "hset",
    "incr",
    "pop",
    "remove",
    "set",
    "setdefault",
    "setex",
    "update",
})


@dataclass(frozen=True)
class TaintFinding:
    """A tainted shared-memory mutation discovered by flow analysis."""

    filename: str
    lineno: int
    function_name: str


def _root_name(node: ast.AST) -> str:
    """Return the local root name referenced by an expression."""
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _has_taint(node: ast.AST, tainted: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(node))


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.Tuple, ast.List)):
        return {name for element in node.elts for name in _target_names(element)}
    name = _root_name(node)
    return {name} if name else set()


def _is_lock_context(node: ast.AST) -> bool:
    return "lock" in ast.unparse(node).lower() or "semaphore" in ast.unparse(node).lower()


def _is_concurrent(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if isinstance(node, ast.AsyncFunctionDef):
        return True
    decorators = " ".join(ast.unparse(decorator).lower() for decorator in node.decorator_list)
    body = " ".join(ast.unparse(statement).lower() for statement in node.body)
    return any(token in decorators or token in body for token in ("thread", "executor", "create_task", ".post", ".put", ".patch"))


def _module_sources(tree: ast.Module) -> set[str]:
    """Identify globals, class attributes, singleton objects, and Redis clients."""
    sources: set[str] = set()
    statements: list[ast.stmt] = list(tree.body)
    for statement in tree.body:
        if isinstance(statement, ast.ClassDef):
            statements.extend(statement.body)
            if any(
                isinstance(candidate, (ast.Assign, ast.AnnAssign))
                and isinstance(candidate.value, (ast.Dict, ast.List, ast.Set))
                for candidate in statement.body
            ):
                # Tainting the class name makes ``Config.cache`` a source
                # without pretending to know every attribute dynamically.
                sources.add(statement.name)
    for statement in statements:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        names = {name for target in targets for name in _target_names(target)}
        if isinstance(value, (ast.Dict, ast.List, ast.Set)):
            sources.update(names)
        elif isinstance(value, ast.Call):
            rendered = ast.unparse(value).lower()
            if "redis" in rendered or any("singleton" in name.lower() or "client" in name.lower() for name in names):
                sources.update(names)
    return sources


class _FunctionFlow:
    """Forward flow within one function, carrying taint through assignments."""

    def __init__(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        filename: str,
        initial_taint: set[str],
    ) -> None:
        self.node = node
        self.filename = filename
        self.tainted = set(initial_taint)
        self.concurrent = _is_concurrent(node)
        self.findings: list[TaintFinding] = []

    def run(self) -> list[TaintFinding]:
        self._statements(self.node.body, locked=False)
        return self.findings

    def _sink(self, target: ast.AST, lineno: int, locked: bool) -> None:
        if self.concurrent and not locked and _root_name(target) in self.tainted:
            self.findings.append(TaintFinding(self.filename, lineno, self.node.name))

    def _statements(self, statements: list[ast.stmt], locked: bool) -> None:
        for statement in statements:
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                protected = locked or any(_is_lock_context(item.context_expr) for item in statement.items)
                self._statements(statement.body, protected)
            elif isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                self._statements(statement.body, locked)
                self._statements(statement.orelse, locked)
            elif isinstance(statement, ast.Try):
                self._statements(statement.body, locked)
                self._statements(statement.orelse, locked)
                self._statements(statement.finalbody, locked)
                for handler in statement.handlers:
                    self._statements(handler.body, locked)
            elif isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if not isinstance(target, ast.Name):
                        self._sink(target, statement.lineno, locked)
                    target_names = _target_names(target)
                    if _has_taint(statement.value, self.tainted):
                        self.tainted.update(target_names)
                    elif isinstance(target, ast.Name):
                        self.tainted.discard(target.id)
            elif isinstance(statement, ast.AnnAssign):
                if statement.value is not None:
                    if not isinstance(statement.target, ast.Name):
                        self._sink(statement.target, statement.lineno, locked)
                    if _has_taint(statement.value, self.tainted):
                        self.tainted.update(_target_names(statement.target))
            elif isinstance(statement, ast.AugAssign):
                self._sink(statement.target, statement.lineno, locked)
            else:
                for call in (child for child in ast.walk(statement) if isinstance(child, ast.Call)):
                    if isinstance(call.func, ast.Attribute) and call.func.attr in _MUTATORS:
                        self._sink(call.func.value, call.lineno, locked)


def _function_ast_by_key(
    files: list[Path], graph: CallGraph
) -> tuple[dict[str, ast.FunctionDef | ast.AsyncFunctionDef], dict[str, set[str]]]:
    """Map call-graph keys to AST definitions and module-level source names."""
    definitions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    source_names: dict[str, set[str]] = {}
    by_location = {(node.filename, node.name): key for key, node in graph.functions.items()}
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        sources = _module_sources(tree)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = by_location.get((str(path), node.name))
                if key:
                    definitions[key] = node
                    source_names[key] = sources
    return definitions, source_names


def find_tainted_shared_state_mutations(files: list[Path], graph: CallGraph) -> list[TaintFinding]:
    """Return CG-015 sink locations after fixed-point inter-procedural flow.

    Parameter taint is propagated along resolved graph call sites until stable.
    It is intentionally conservative: unsupported expressions do not invent a
    taint relationship, avoiding broad false positives.
    """
    definitions, sources = _function_ast_by_key(files, graph)
    parameter_taint: dict[str, set[str]] = {key: set() for key in definitions}
    for _ in range(max(1, len(definitions))):
        changed = False
        effective: dict[str, set[str]] = {}
        for key, node in definitions.items():
            flow = _FunctionFlow(node, graph.functions[key].filename, sources[key] | parameter_taint[key])
            flow.run()
            effective[key] = flow.tainted
        for site in graph.call_sites:
            caller_taint = effective.get(site.source, set())
            callee = definitions.get(site.target)
            if callee is None:
                continue
            parameters = callee.args.posonlyargs + callee.args.args
            for index, argument in enumerate(site.arguments):
                if index < len(parameters) and argument in caller_taint and parameters[index].arg not in parameter_taint[site.target]:
                    parameter_taint[site.target].add(parameters[index].arg)
                    changed = True
        if not changed:
            break

    findings: list[TaintFinding] = []
    for key, node in definitions.items():
        findings.extend(_FunctionFlow(node, graph.functions[key].filename, sources[key] | parameter_taint[key]).run())
    return list(dict.fromkeys(findings))


def find_tainted_shared_state_mutations_in_source(source: str, filename: str) -> list[TaintFinding]:
    """Analyze one in-memory module using the same forward-flow implementation."""
    tree = ast.parse(source, filename=filename)
    graph = CallGraph()
    sources = _module_sources(tree)
    findings: list[TaintFinding] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            graph.functions[node.name] = FunctionNode(node.name, filename, node.lineno, node.name, isinstance(node, ast.AsyncFunctionDef))
            findings.extend(_FunctionFlow(node, filename, sources).run())
    return list(dict.fromkeys(findings))

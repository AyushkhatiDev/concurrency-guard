"""Project-wide lock order with a source witness for every acquisition."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from concurrency_guard.cfg import CFGLimitError, build_function_cfg, lock_states, query_info
from concurrency_guard.project_graph import ProjectSymbolGraph
from concurrency_guard.scanner.ast_rules import ASTFinding


@dataclass(frozen=True, order=True)
class Acquisition:
    file: Path
    function: str
    line: int


@dataclass
class LockOrderGraph:
    edges: dict[str, dict[str, set[Acquisition]]] = field(default_factory=dict)

    def add(self, first: str, second: str, source: Acquisition) -> None:
        if first != second:
            self.edges.setdefault(first, {}).setdefault(second, set()).add(source)

    def findings(self, root: Path) -> Iterable[ASTFinding]:
        def walk(path: tuple[str, ...]) -> Iterable[ASTFinding]:
            for nxt in sorted(self.edges.get(path[-1], {})):
                if nxt == path[0]:
                    pairs = list(zip(path, (*path[1:], nxt)))
                    options = [sorted(self.edges[a][b]) for a, b in pairs]
                    sites = [choices[0] for choices in options]
                    if len({site.file for site in sites}) == 1:
                        alternative = next(
                            (
                                (i, site)
                                for i, choices in enumerate(options)
                                for site in choices
                                if site.file != sites[0].file
                            ),
                            None,
                        )
                        if alternative is None:
                            continue
                        i, replacement = alternative
                        sites[i] = replacement
                    trace = []
                    for (a, b), site in zip(pairs, sites):
                        file = (
                            site.file.relative_to(root)
                            if site.file.is_relative_to(root)
                            else site.file
                        )
                        trace.append(
                            f"{file}:{site.line} ({a.split('::')[-1]} -> {b.split('::')[-1]})"
                        )
                    first = sites[0]
                    yield ASTFinding(
                        "CG-029",
                        str(first.file),
                        first.line,
                        first.function,
                        "Cross-file lock-order inversion: " + " <-> ".join(trace),
                        "Acquire these resources in the same order in every function.",
                    )
                elif nxt > path[0] and nxt not in path:
                    yield from walk((*path, nxt))

        for start in sorted(self.edges):
            yield from walk((start,))


def project_deadlocks(
    modules: Iterable[tuple[Path, ast.Module]], graph: ProjectSymbolGraph
) -> Iterable[ASTFinding]:
    orders = LockOrderGraph()
    modules = list(modules)
    known_locks = {
        (path, target.id)
        for path, module in modules
        for assignment in module.body
        if isinstance(assignment, (ast.AnnAssign, ast.Assign))
        and isinstance(assignment.value, ast.Call)
        and ast.unparse(assignment.value.func).split(".")[-1] in {"Lock", "RLock"}
        for target in (
            assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        )
        if isinstance(target, ast.Name)
    }
    for file, tree in modules:
        imports = graph.imports_by_file.get(file, {})
        declared = {
            t.id
            for stmt in tree.body
            if isinstance(stmt, ast.Assign)
            for t in stmt.targets
            if isinstance(t, ast.Name)
        }

        def identity(
            name: str,
            imports: dict[str, tuple[Path, str]] = imports,
            file: Path = file,
            declared: set[str] = declared,
        ) -> str:
            head, _, rest = name.partition(".")
            if head in imports:
                dest, symbol = imports[head]
                return f"{dest}::{'.'.join(filter(None, (symbol if symbol != '*' else '', rest)))}"
            return f"{file}::{name}" if head in declared else name

        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }

        def is_lock(
            name: str, file: Path = file, imports: dict[str, tuple[Path, str]] = imports
        ) -> bool:
            if "(" in name:
                return False
            head, _, tail = name.partition(".")
            dest, symbol = imports.get(head, (file, head))
            key = (dest, tail if symbol == "*" else symbol)
            return key in known_locks or "lock" in name.lower()

        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(
                isinstance(n, (ast.With, ast.AsyncWith))
                or isinstance(n, ast.Attribute)
                and n.attr == "with_for_update"
                for n in ast.walk(fn)
            ):
                continue
            qualified = fn.name
            parent = parents.get(fn)
            while parent:
                if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualified = f"{parent.name}.{qualified}"
                parent = parents.get(parent)
            try:
                cfg = build_function_cfg(fn)
            except CFGLimitError:
                continue
            for i, states in lock_states(cfg).items():
                block = cfg.blocks[i]
                for stmt in block.stmts:
                    context = [name for name in block.context if is_lock(name)]
                    for rows, bindings in states:
                        prior = [*sorted(rows), *context]
                        acquired: list[str] = []
                        if isinstance(stmt, (ast.With, ast.AsyncWith)):
                            acquired = [
                                ast.unparse(item.context_expr)
                                for item in stmt.items
                                if is_lock(ast.unparse(item.context_expr))
                            ]
                        elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Return)):
                            model, locked, executed = query_info(stmt, bindings)
                            if model and locked and executed:
                                acquired.append(model)
                        for name in acquired:
                            for prev in prior:
                                orders.add(
                                    identity(prev),
                                    identity(name),
                                    Acquisition(file, qualified, stmt.lineno),
                                )
                            prior.append(name)
    return orders.findings(graph.roots[0])

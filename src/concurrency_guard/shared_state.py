"""Read, suspension and write analysis for shared Python state."""

from __future__ import annotations

import ast
from collections import deque
from collections.abc import Iterator

from concurrency_guard.cfg import CFGLimitError, build_function_cfg


def shared_writes(tree: ast.Module) -> Iterator[tuple[ast.AST, str, str]]:
    aliases: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.ImportFrom, ast.Import)):
            for item in stmt.names:
                prefix = (stmt.module or "") + "." if isinstance(stmt, ast.ImportFrom) else ""
                aliases[item.asname or item.name] = prefix + item.name

    def declarations(body: list[ast.stmt]) -> tuple[set[str], set[str]]:
        shared: set[str] = set()
        locks: set[str] = set()
        for s in body:
            if not isinstance(s, (ast.Assign, ast.AnnAssign)) or s.value is None:
                continue
            for t in s.targets if isinstance(s, ast.Assign) else [s.target]:
                if not isinstance(t, ast.Name):
                    continue
                if isinstance(s.value, ast.Call):
                    name = ast.unparse(s.value.func)
                    head, dot, tail = name.partition(".")
                    if aliases.get(head, head) + dot + tail in {"asyncio.Lock", "anyio.Lock"}:
                        locks.add(t.id)
                    if name in {"list", "dict", "set", "int"}:
                        shared.add(t.id)
                elif isinstance(s.value, (ast.Dict, ast.List, ast.Set)) or (
                    isinstance(s.value, ast.Constant) and isinstance(s.value.value, int)
                ):
                    shared.add(t.id)
        return shared, locks

    globals_, locks = declarations(tree.body)
    for owner, body in [
        ("", tree.body),
        *((s.name, s.body) for s in tree.body if isinstance(s, ast.ClassDef)),
    ]:
        attrs, class_locks = declarations(body) if owner else (set(), set())
        for fn in body:
            if not isinstance(fn, ast.AsyncFunctionDef):
                continue

            def local_walk(node: ast.AST) -> Iterator[ast.AST]:
                for child in ast.iter_child_nodes(node):
                    if not isinstance(
                        child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
                    ):
                        yield child
                        yield from local_walk(child)

            nodes = list(local_walk(fn))
            if not any(isinstance(n, ast.Await) for n in nodes):
                continue
            local = {
                n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
            }
            local.update(n.arg for n in nodes if isinstance(n, ast.arg))
            local -= {name for n in nodes if isinstance(n, ast.Global) for name in n.names}
            names = {n: n for n in globals_ - local}
            guards = locks - local
            for prefix in ("self", "cls", owner):
                names.update({f"{prefix}.{n}": f"{owner}.{n}" for n in attrs})
                guards.update(f"{prefix}.{n}" for n in class_locks)
            if not names:
                continue

            def events(
                n: ast.AST, names: dict[str, str] = names
            ) -> Iterator[tuple[str, str, ast.AST]]:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    return
                if isinstance(n, ast.Assign):
                    yield from events(n.value)
                    for t in n.targets:
                        yield from events(t)
                    return
                if isinstance(n, ast.AugAssign):
                    key = ast.unparse(n.target).split("[")[0]
                    if key in names:
                        yield "read", names[key], n
                    yield from events(n.value)
                    if key in names:
                        yield "write", names[key], n
                    return
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    key = ast.unparse(n.func.value)
                    if key in names and n.func.attr in {
                        "append",
                        "add",
                        "pop",
                        "update",
                        "extend",
                        "clear",
                        "remove",
                    }:
                        for arg in [*n.args, *n.keywords]:
                            yield from events(arg)
                        yield "write", names[key], n
                        return
                for child in ast.iter_child_nodes(n):
                    if not isinstance(child, (ast.stmt, ast.excepthandler)):
                        yield from events(child)
                if isinstance(n, ast.Await):
                    yield "await", "", n
                if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript)):
                    key = ast.unparse(n).split("[")[0]
                    if key in names:
                        yield "write" if isinstance(n.ctx, ast.Store) else "read", names[key], n

            try:
                cfg = build_function_cfg(fn)
            except CFGLimitError:
                continue
            # Track one pending read per traversal, including locks held continuously since it.
            State = tuple[int, str, bool, frozenset[str]]
            work: deque[State] = deque([(cfg.entry, "", False, frozenset())])
            seen: set[State] = set()
            reported: set[tuple[int, str]] = set()
            while work:
                state = work.popleft()
                if state in seen:
                    continue
                seen.add(state)
                index, name, crossed, held = state
                block = cfg.blocks[index]
                active = frozenset(block.context).intersection(guards)
                paths = {(name, crossed, held & active)}
                for s in block.stmts:
                    for kind, key, site in events(s):
                        if kind == "await":
                            paths = {(r, bool(r), h) for r, _, h in paths}
                        elif kind == "read":
                            paths.add((key, False, active))
                        elif (id(site), key) not in reported and any(
                            r == key and a and not h for r, a, h in paths
                        ):
                            reported.add((id(site), key))
                            yield site, fn.name, key
                for dst in block.successors:
                    work.extend((dst, r, a, h) for r, a, h in paths)

"""Control flow and path-sensitive lock facts for a single Python function."""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Union

Function = Union[ast.FunctionDef, ast.AsyncFunctionDef]


@dataclass
class BasicBlock:
    id: int
    stmts: list[ast.stmt] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    context: tuple[str, ...] = ()


@dataclass
class FunctionCFG:
    blocks: list[BasicBlock]
    entry: int
    exit: int
    exceptional: set[tuple[int, int]]
    guards: dict[tuple[int, int], tuple[str, bool]]
    dominators: dict[int, set[int]]


def expression_nodes(stmt: ast.stmt) -> list[ast.AST]:
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return []
    return [
        node
        for expr in ast.iter_child_nodes(stmt)
        if isinstance(expr, ast.expr)
        for node in ast.walk(expr)
    ]


def build_function_cfg(func_node: Function) -> FunctionCFG:
    blocks: list[BasicBlock] = []
    exceptional: set[tuple[int, int]] = set()
    guards: dict[tuple[int, int], tuple[str, bool]] = {}

    def block(stmt: Optional[ast.stmt], ctx: tuple[str, ...]) -> int:
        index = len(blocks)
        blocks.append(BasicBlock(index, [stmt] if stmt else [], context=ctx))
        return index

    def edge(src: int, dst: int) -> None:
        if dst not in blocks[src].successors:
            blocks[src].successors.append(dst)
            blocks[dst].predecessors.append(src)

    end = block(None, ())

    def suite(
        body: list[ast.stmt],
        after: int,
        ret: int,
        exc: int,
        brk: int,
        cont: int,
        ctx: tuple[str, ...],
    ) -> int:
        for stmt in reversed(body):
            current = block(stmt, ctx)

            def child(items: list[ast.stmt], dest: int) -> int:
                return suite(items, dest, ret, exc, brk, cont, ctx)

            if isinstance(stmt, ast.If):
                for items, truth in ((stmt.body, True), (stmt.orelse, False)):
                    dest = child(items, after)
                    edge(current, dest)
                    test = stmt.test
                    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                        truth, test = not truth, test.operand
                    if isinstance(test, ast.Name):
                        guards[current, dest] = (test.id, truth)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                edge(current, suite(stmt.body, current, ret, exc, after, current, ctx))
                edge(current, child(stmt.orelse, after))
            elif isinstance(stmt, ast.Try):

                def cleanup(dest: int, body: list[ast.stmt] = stmt.finalbody) -> int:
                    return child(body, dest)

                normal, returning, raised = cleanup(after), cleanup(ret), cleanup(exc)
                breaking, continuing = cleanup(brk), cleanup(cont)
                dispatch = block(None, ctx)
                edge(dispatch, raised)
                for handler in stmt.handlers:
                    edge(
                        dispatch,
                        suite(handler.body, normal, returning, raised, breaking, continuing, ctx),
                    )
                otherwise = suite(stmt.orelse, normal, returning, raised, breaking, continuing, ctx)
                edge(
                    current,
                    suite(stmt.body, otherwise, returning, dispatch, breaking, continuing, ctx),
                )
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                names = tuple(ast.unparse(item.context_expr) for item in stmt.items)
                edge(current, suite(stmt.body, after, ret, exc, brk, cont, ctx + names))
            else:
                target = {ast.Return: ret, ast.Raise: exc, ast.Break: brk, ast.Continue: cont}
                edge(current, target.get(type(stmt), after))
            if exc != end and (
                expression_nodes(stmt) or isinstance(stmt, (ast.With, ast.AsyncWith))
            ):
                failure = block(None, ctx)
                edge(current, failure)
                exceptional.add((current, failure))
                edge(failure, exc)
            after = current
        return after

    entry = suite(func_node.body, end, end, end, end, end, ())
    reachable: set[int] = set()
    todo = [entry]
    while todo:
        index = todo.pop()
        if index not in reachable:
            reachable.add(index)
            todo.extend(blocks[index].successors)
    dom = {i: ({i} if i == entry else reachable.copy()) for i in reachable}
    changed = True
    while changed:
        changed = False
        for i in sorted(reachable - {entry}):
            value = {i} | set.intersection(
                *(dom[p] for p in blocks[i].predecessors if p in reachable)
            )
            if value != dom[i]:
                dom[i], changed = value, True
    return FunctionCFG(blocks, entry, end, exceptional, guards, dom)


@dataclass(frozen=True)
class LockFacts:
    must: frozenset[str]
    may: frozenset[str]


def query_info(expr: ast.AST, bindings: dict[str, str]) -> tuple[str, bool, bool]:
    """Return model identity, FOR UPDATE intent and whether the query executes."""
    if isinstance(expr, (ast.Assign, ast.AnnAssign)):
        if expr.value is None:
            return "", False, False
        expr = expr.value
    model = ""
    locked = False
    executes = False
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func).split(".")[-1]
            if name == "select" and node.args:
                model = ast.unparse(node.args[0])
            if name in {"get", "execute", "exec", "scalar", "scalars"} and node.args:
                executes = True
                if name == "get":
                    model = ast.unparse(node.args[0])
            locked |= name == "with_for_update"
        if isinstance(node, ast.Name) and node.id in bindings:
            source = bindings[node.id]
            if source.startswith(("query:", "lockedquery:")):
                kind, model = source.split(":", 1)
                locked |= kind == "lockedquery"
    return model, locked, executes


def lock_states(cfg: FunctionCFG) -> dict[int, list[tuple[frozenset[str], dict[str, str]]]]:
    states: dict[int, list[tuple[frozenset[str], dict[str, str]]]] = {}
    work: deque[tuple[int, frozenset[str], dict[str, str]]] = deque([(cfg.entry, frozenset(), {})])
    while work:
        index, held, bindings = work.popleft()
        seen = states.setdefault(index, [])
        if (held, bindings) in seen:
            continue
        seen.append((held, bindings))
        block = cfg.blocks[index]
        new, env = set(held), bindings.copy()
        for stmt in block.stmts:
            model, locked, executes = (
                query_info(stmt, env)
                if not isinstance(
                    stmt,
                    (
                        ast.If,
                        ast.Try,
                        ast.For,
                        ast.AsyncFor,
                        ast.While,
                        ast.With,
                        ast.AsyncWith,
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.ClassDef,
                    ),
                )
                else ("", False, False)
            )
            if executes and locked and model:
                new.add(model)
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                value = stmt.value
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        env.pop(t.id, None)
                        if isinstance(value, ast.Name) and value.id in bindings:
                            env[t.id] = bindings[value.id]
                        elif model:
                            prefix = (
                                ("lockedentity" if locked else "entity")
                                if executes
                                else "lockedquery"
                                if locked
                                else "query"
                            )
                            env[t.id] = f"{prefix}:{model}"
                        elif isinstance(value, ast.Constant) and isinstance(value.value, bool):
                            env[t.id] = str(value.value)
            if any(
                isinstance(n, ast.Attribute) and n.attr in {"commit", "rollback"}
                for n in expression_nodes(stmt)
            ):
                new.clear()
        for dst in block.successors:
            guard = cfg.guards.get((index, dst))
            if guard and env.get(guard[0]) == str(not guard[1]):
                continue
            if (index, dst) in cfg.exceptional:
                work.append((dst, held, bindings))
            else:
                leaves_transaction = any(
                    name.endswith((".begin()", ".begin_nested()"))
                    and name not in cfg.blocks[dst].context
                    for name in block.context
                )
                work.append((dst, frozenset() if leaves_transaction else frozenset(new), env))
    return states


def compute_locked_paths(cfg: FunctionCFG) -> dict[ast.stmt, LockFacts]:
    result: dict[ast.stmt, LockFacts] = {}
    for i, paths in lock_states(cfg).items():
        block = cfg.blocks[i]
        for stmt in block.stmts:
            for held, env in paths:
                locks = held.union(name for name in block.context if "lock" in name.lower())
                locks = locks.union(
                    k
                    for k, v in env.items()
                    if v.startswith("lockedentity:") and v.partition(":")[2] in held
                )
                prev = result.get(stmt)
                result[stmt] = (
                    LockFacts(locks & prev.must, locks | prev.may)
                    if prev
                    else LockFacts(locks, locks)
                )
    return result


def mutation_protection(func: Function) -> tuple[set[int], dict[int, str], set[int], set[int]]:
    """Classify mutations with a reachable commit and a sibling protection witness."""
    cfg = build_function_cfg(func)
    states = lock_states(cfg)
    protected: set[int] = set()
    partial: dict[int, str] = {}
    unlocked: set[int] = set()
    live = {
        id(n)
        for i in states
        for stmt in cfg.blocks[i].stmts
        for n in [stmt, *expression_nodes(stmt)]
    }

    def reachable(start: int) -> set[int]:
        found: set[int] = set()
        work = [start]
        while work:
            i = work.pop()
            if i not in found and i in states:
                found.add(i)
                work.extend(cfg.blocks[i].successors)
        return found

    commits = {
        i
        for i in states
        for stmt in cfg.blocks[i].stmts
        if any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in {"commit", "save", "flush"}
            for n in expression_nodes(stmt)
        )
    }
    for i, paths in states.items():
        for stmt in cfg.blocks[i].stmts:
            if isinstance(stmt, ast.Assign):
                targets = stmt.targets
            elif isinstance(stmt, ast.AugAssign):
                targets = [stmt.target]
            else:
                continue
            for target in targets:
                if not isinstance(target, (ast.Attribute, ast.Subscript)):
                    continue
                root = ast.unparse(target.value).split(".")[0]
                held_here = []
                models = set()
                for held, env in paths:
                    kind, _, model = env.get(root, "").partition(":")
                    if kind not in {"entity", "lockedentity"}:
                        model = ""
                    if model:
                        models.add(model)
                    held_here.append(kind == "lockedentity" and model in held)
                if all(held_here):
                    protected.add(id(stmt))
                    continue
                if models:
                    unlocked.add(id(stmt))
                if not commits.intersection(reachable(i)):
                    continue
                if any("lock" in name.lower() for name in cfg.blocks[i].context):
                    continue
                witness = any(held_here)
                for branch in cfg.blocks:
                    if witness or branch.id not in cfg.dominators[i] or len(branch.successors) < 2:
                        continue
                    arms = [reachable(s) for s in branch.successors]
                    if any(i in reachable(dst) for src, dst in cfg.exceptional if src == branch.id):
                        for operation in branch.stmts:
                            if isinstance(operation, (ast.Expr, ast.Assign, ast.AnnAssign)):
                                for _, bindings in states[branch.id]:
                                    model, locked, executed = query_info(operation, bindings)
                                    if locked and executed and model in models:
                                        witness = True
                    for arm in arms:
                        if i in arm:
                            continue
                        for j in arm.difference(
                            *(other_arm for other_arm in arms if i in other_arm)
                        ):
                            for acquisition in cfg.blocks[j].stmts:
                                if isinstance(acquisition, (ast.Assign, ast.AnnAssign, ast.Expr)):
                                    for _, bindings in states[j]:
                                        model, locked, executed = query_info(acquisition, bindings)
                                        if locked and executed and model in models:
                                            witness = True
                            other = cfg.blocks[j]
                            if any("lock" in name.lower() for name in other.context) and any(
                                isinstance(n, ast.Name) and n.id == root
                                for s in other.stmts
                                for n in expression_nodes(s)
                            ):
                                witness = True
                if witness:
                    partial[id(stmt)] = root
    return protected - unlocked, partial, live, unlocked

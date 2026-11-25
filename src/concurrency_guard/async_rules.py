"""Static checks for structured concurrency."""
from __future__ import annotations

import ast
from collections.abc import Iterator


def local_nodes(root: ast.AST) -> Iterator[ast.AST]:
    for child in ast.iter_child_nodes(root):
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            yield child
            yield from local_nodes(child)


def asyncio_names(module: ast.AST) -> dict[str, str]:
    names = {"asyncio": "asyncio"}
    if isinstance(module, ast.Module):
        for stmt in module.body:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    if alias.name == "asyncio":
                        names[alias.asname or alias.name] = "asyncio"
            elif isinstance(stmt, ast.ImportFrom) and stmt.module == "asyncio" and stmt.level == 0:
                for alias in stmt.names:
                    names[alias.asname or alias.name] = f"asyncio.{alias.name}"
    return names


def qualified(expr: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(expr, ast.Name):
        return aliases.get(expr.id, expr.id)
    if isinstance(expr, ast.Attribute):
        return f"{qualified(expr.value, aliases)}.{expr.attr}"
    return ""


def shared_sessions(
    function: ast.AsyncFunctionDef, aliases: dict[str, str],
) -> Iterator[tuple[ast.AST, str]]:
    session_names = {"db", "session", "async_session"}
    for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
        if arg.annotation is not None:
            annotation = ast.unparse(arg.annotation)
            if "AsyncSession" in annotation:
                session_names.add(arg.arg)
            elif annotation not in {"Any", "typing.Any"}:
                session_names.discard(arg.arg)

    nodes = list(local_nodes(function))
    factories = {"async_sessionmaker"}
    for node in nodes:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            constructor = qualified(node.value.func, aliases).split(".")[-1]
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if constructor == "async_sessionmaker":
                    factories.add(target.id)
                elif constructor == "AsyncSession" or constructor in factories:
                    session_names.add(target.id)
        elif isinstance(node, ast.AsyncWith):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and isinstance(item.optional_vars, ast.Name):
                    constructor = qualified(item.context_expr.func, aliases).split(".")[-1]
                    if constructor == "AsyncSession" or constructor in factories:
                        session_names.add(item.optional_vars.id)

    def duplicates(coroutines: list[ast.expr]) -> set[str]:
        seen: set[str] = set()
        repeated: set[str] = set()
        for coroutine in coroutines:
            if not isinstance(coroutine, ast.Call):
                continue
            arguments = [
                *coroutine.args,
                *(keyword.value for keyword in coroutine.keywords),
            ]
            current = {arg.id for arg in arguments if isinstance(arg, ast.Name)} & session_names
            if isinstance(coroutine.func, ast.Attribute) and isinstance(coroutine.func.value, ast.Name):
                current |= {coroutine.func.value.id} & session_names
            repeated.update(current & seen)
            seen.update(current)
        return repeated

    for node in nodes:
        if isinstance(node, ast.Call) and qualified(node.func, aliases) == "asyncio.gather":
            for session in sorted(duplicates(node.args)):
                yield node, session
        elif isinstance(node, ast.AsyncWith):
            for item in node.items:
                if (isinstance(item.context_expr, ast.Call)
                        and qualified(item.context_expr.func, aliases) == "asyncio.TaskGroup"
                        and isinstance(item.optional_vars, ast.Name)):
                    task_method = f"{item.optional_vars.id}.create_task"
                    tasks = [
                        child.args[0] for stmt in node.body for child in (stmt, *local_nodes(stmt))
                        if isinstance(child, ast.Call) and child.args
                        and qualified(child.func, {}) == task_method
                    ]
                    for session in sorted(duplicates(tasks)):
                        yield node, session

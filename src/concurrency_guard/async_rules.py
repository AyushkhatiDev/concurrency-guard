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


def session_symbols(module: ast.AST | None) -> dict[str, str]:
    symbols = {"AsyncSession": "session", "async_sessionmaker": "maker"}
    if isinstance(module, ast.Module):
        for stmt in module.body:
            if isinstance(stmt, ast.ImportFrom) and (stmt.module or "").split(".")[0] in {"sqlalchemy", "sqlmodel"}:
                for alias in stmt.names:
                    if alias.name in symbols:
                        symbols[alias.asname or alias.name] = symbols[alias.name]
            if (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)
                    and symbols.get(qualified(stmt.value.func, {}).split(".")[-1]) == "maker"):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        symbols[target.id] = "factory"
    return symbols


def shared_sessions(
    function: ast.AsyncFunctionDef, aliases: dict[str, str], symbols: dict[str, str],
) -> Iterator[tuple[ast.AST, str, tuple[ast.AST, ast.AST, ast.AST]]]:
    # Each binding carries its allocation site, including through local aliases.
    bindings: dict[str, tuple[str, ast.AST]] = {}
    for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
        annotation = ast.unparse(arg.annotation).strip("'\u0022") if arg.annotation else "Any"
        if (symbols.get(annotation.split(".")[-1]) == "session" or
                annotation in {"Any", "typing.Any"} and arg.arg in {"db", "session", "async_session"}):
            bindings[arg.arg] = ("session", arg)

    results: list[tuple[ast.AST, str, tuple[ast.AST, ast.AST, ast.AST]]] = []
    guards: dict[ast.If, bool] = {}
    groups: dict[str, ast.AsyncWith] = {}
    history: dict[tuple[ast.AST, ast.AST], list[tuple[ast.AST, dict[ast.If, bool]]]] = {}
    reported: set[tuple[ast.AST, ast.AST]] = set()

    def bind(name: ast.expr, value: ast.expr | None) -> None:
        if not isinstance(name, ast.Name):
            return
        binding = bindings.get(value.id) if isinstance(value, ast.Name) else None
        if isinstance(value, ast.Call):
            callee = qualified(value.func, {}).split(".")[-1]
            kind = bindings[callee][0] if callee in bindings else symbols.get(callee)
            if kind in {"session", "factory", "maker"}:
                binding = ("factory" if kind == "maker" else "session", name)
        if binding:
            bindings[name.id] = binding
        else:
            bindings.pop(name.id, None)

    def record(owner: ast.AST, site: ast.AST, coroutine: ast.expr) -> None:
        if not isinstance(coroutine, ast.Call):
            return
        args = [*coroutine.args, *(kw.value for kw in coroutine.keywords)]
        if isinstance(coroutine.func, ast.Attribute):
            args.append(coroutine.func.value)
        for arg in args:
            if not isinstance(arg, ast.Name) or arg.id not in bindings:
                continue
            kind, origin = bindings[arg.id]
            key = (owner, origin)
            if kind != "session" or key in reported:
                continue
            prior = history.setdefault(key, [])
            for other, conditions in prior:
                if other is not site and all(guards.get(k, v) == v for k, v in conditions.items()):
                    results.append((owner, arg.id, (origin, other, site)))
                    reported.add(key)
                    break
            if not prior or prior[-1][0] is not site:
                prior.append((site, guards.copy()))

    def walk(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return
        if isinstance(node, ast.If):
            walk(node.test)
            before = bindings.copy()
            guards[node] = True
            for stmt in node.body:
                walk(stmt)
            left = bindings.copy()
            bindings.clear()
            bindings.update(before)
            guards[node] = False
            for stmt in node.orelse:
                walk(stmt)
            del guards[node]
            for name in list(bindings):
                if bindings[name] != left.get(name):
                    del bindings[name]
            return
        if isinstance(node, ast.AsyncWith):
            previous = groups.copy()
            for item in node.items:
                walk(item.context_expr)
                if item.optional_vars is not None:
                    bind(item.optional_vars, item.context_expr)
                if (isinstance(item.optional_vars, ast.Name) and isinstance(item.context_expr, ast.Call)
                        and qualified(item.context_expr.func, aliases) == "asyncio.TaskGroup"):
                    groups[item.optional_vars.id] = node
            for stmt in node.body:
                walk(stmt)
            groups.clear()
            groups.update(previous)
            return
        if isinstance(node, ast.Call):
            if qualified(node.func, aliases) == "asyncio.gather":
                for coroutine in node.args:
                    record(node, coroutine, coroutine)
            elif (isinstance(node.func, ast.Attribute) and node.func.attr == "create_task"
                  and isinstance(node.func.value, ast.Name) and node.func.value.id in groups and node.args):
                record(groups[node.func.value.id], node, node.args[0])
        for child in ast.iter_child_nodes(node):
            walk(child)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bind(node.target, node.value)

    for stmt in function.body:
        walk(stmt)
    yield from results


def async_lock_contexts(root: ast.AST) -> Iterator[tuple[ast.AsyncWith, list[str]]]:
    for statement in local_nodes(root):
        if isinstance(statement, ast.AsyncWith):
            locks = [
                qualified(item.context_expr, {}) for item in statement.items
                if isinstance(item.context_expr, (ast.Name, ast.Attribute))
            ]
            yield statement, locks


def is_async_lock_name(name: str) -> bool:
    return "lock" in name.lower() and not any(
        marker in name.lower() for marker in ("rlock", "reentrant")
    )


def handler_reraises(body: list[ast.stmt], exception_name: str | None) -> bool:
    def outcomes(statements: list[ast.stmt]) -> set[str]:
        paths = {"next"}
        for stmt in statements:
            if "next" not in paths:
                break
            paths.remove("next")
            if isinstance(stmt, ast.Raise):
                same = stmt.exc is None or isinstance(stmt.exc, ast.Name) and stmt.exc.id == exception_name
                paths.add("raise" if same else "stop")
            elif isinstance(stmt, (ast.Return, ast.Break, ast.Continue)):
                paths.add("stop")
            elif isinstance(stmt, ast.Try):
                attempted = outcomes(stmt.body)
                if "next" in attempted:
                    attempted.remove("next")
                    attempted.update(outcomes(stmt.orelse))
                for handler in stmt.handlers:
                    attempted.update(outcomes(handler.body))
                cleanup = outcomes(stmt.finalbody)
                paths.update(cleanup - {"next"})
                if "next" in cleanup:
                    paths.update(attempted)
            elif isinstance(stmt, ast.If):
                if isinstance(stmt.test, ast.Constant):
                    paths.update(outcomes(stmt.body if stmt.test.value else stmt.orelse))
                else:
                    paths.update(outcomes(stmt.body) | outcomes(stmt.orelse))
            elif isinstance(stmt, ast.Try):
                inner = outcomes(stmt.body)
                if "next" in inner:
                    inner = (inner - {"next"}) | outcomes(stmt.orelse)
                for handler in stmt.handlers:
                    inner.update(outcomes(handler.body))
                final = outcomes(stmt.finalbody)
                paths.update((inner if "next" in final else set()) | (final - {"next"}))
            else:
                paths.add("next")
                if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                    paths.update(outcomes(stmt.body) - {"next"})
        return paths

    return outcomes(body) == {"raise"}


def swallowed_cancellation(
    function: ast.AsyncFunctionDef, aliases: dict[str, str],
) -> Iterator[ast.ExceptHandler]:
    for node in local_nodes(function):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            catch_types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
            names = {qualified(item, aliases) for item in catch_types if item is not None}
            broad = handler.type is None or bool(names & {"BaseException", "builtins.BaseException"})
            if broad or names & {"asyncio.CancelledError", "CancelledError"}:
                if not handler_reraises(handler.body, handler.name):
                    yield handler
                break

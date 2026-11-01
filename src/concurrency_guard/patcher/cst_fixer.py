"""Deterministic LibCST auto-patcher for concurrency locking and idempotency."""

from __future__ import annotations

import libcst as cst
from libcst.metadata import MetadataWrapper, ParentNodeProvider

from concurrency_guard.scanner.ast_rules import scan_source_code


def _is_select_chain(node: cst.CSTNode) -> bool:
    """Check if node is a select(...) call or chained method call on select(...)."""
    if not isinstance(node, cst.Call):
        return False
    func = node.func
    if isinstance(func, cst.Name) and func.value == "select":
        return True
    if isinstance(func, cst.Attribute) and func.attr.value == "select":
        return True
    if isinstance(func, cst.Attribute) and isinstance(func.value, cst.Call):
        return _is_select_chain(func.value)
    return False


def _get_module_name(node: cst.CSTNode | None) -> str:
    """Extract dotted module or variable name from CST node."""
    if node is None:
        return ""
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        parent = _get_module_name(node.value)
        return f"{parent}.{node.attr.value}" if parent else node.attr.value
    return ""


class _WithForUpdateChecker(cst.CSTVisitor):
    """Visitor to detect whether a function contains .with_for_update()."""

    def __init__(self) -> None:
        super().__init__()
        self.has_with_for_update = False

    def visit_Name(self, node: cst.Name) -> None:
        if node.value == "with_for_update":
            self.has_with_for_update = True


def _func_has_with_for_update(fn: cst.FunctionDef) -> bool:
    """Check if function definition already contains .with_for_update()."""
    checker = _WithForUpdateChecker()
    fn.visit(checker)
    return checker.has_with_for_update


def _ensure_import(tree: cst.Module, module_name: str, import_name: str) -> cst.Module:
    """Ensure that import_name is imported from module_name in the module tree."""
    has_import = False
    has_from_mod = False

    for stmt in tree.body:
        if isinstance(stmt, cst.SimpleStatementLine):
            for s in stmt.body:
                if isinstance(s, cst.ImportFrom) and not isinstance(s.names, cst.ImportStar):
                    mod_str = _get_module_name(s.module)
                    if mod_str == module_name:
                        has_from_mod = True
                        for alias in s.names:
                            if alias.name.value == import_name:
                                has_import = True
    if has_import:
        return tree

    class AddToFrom(cst.CSTTransformer):
        def leave_ImportFrom(
            self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
        ) -> cst.ImportFrom:
            if isinstance(updated_node.names, cst.ImportStar):
                return updated_node
            mod_str = _get_module_name(updated_node.module)
            if mod_str == module_name:
                names = [a.name.value for a in updated_node.names]
                if import_name not in names:
                    new_alias = cst.ImportAlias(name=cst.Name(import_name))
                    old = list(updated_node.names)
                    if old and not old[-1].comma:
                        old[-1] = old[-1].with_changes(
                            comma=cst.Comma(whitespace_after=cst.SimpleWhitespace(" "))
                        )
                    return updated_node.with_changes(names=tuple(old + [new_alias]))
            return updated_node

    if has_from_mod:
        return tree.visit(AddToFrom())

    new_stmt = cst.parse_statement(f"from {module_name} import {import_name}\n")
    body: list[cst.SimpleStatementLine | cst.BaseCompoundStatement] = list(tree.body)
    insert_idx = 0
    for idx, stmt_node in enumerate(body):
        if isinstance(stmt_node, cst.SimpleStatementLine) and any(
            isinstance(x, cst.ImportFrom) and getattr(x.module, "value", "") == "__future__"
            for x in stmt_node.body
        ):
            insert_idx = idx + 1
    body.insert(insert_idx, new_stmt)
    return tree.with_changes(body=tuple(body))


class WithForUpdateTransformer(cst.CSTTransformer):
    """LibCST transformer that appends .with_for_update() to unlocked select statements."""

    METADATA_DEPENDENCIES = (ParentNodeProvider,)

    def __init__(self, target_functions: set[str] | None = None) -> None:
        super().__init__()
        self.target_functions = target_functions
        self._current_async_func: cst.FunctionDef | None = None
        self._func_needs_fix: bool = False

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        """Inspect async function entry."""
        if node.asynchronous is not None:
            if self.target_functions is None:
                self._current_async_func = node
                self._func_needs_fix = not _func_has_with_for_update(node)
            elif node.name.value in self.target_functions:
                self._current_async_func = node
                self._func_needs_fix = True
        return True

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        """Clear state on async function exit."""
        if original_node.asynchronous is not None and self._current_async_func is original_node:
            self._current_async_func = None
            self._func_needs_fix = False
        return updated_node

    def leave_Call(self, original_node: cst.Call, updated_node: cst.Call) -> cst.Call:
        """Append .with_for_update() to the outermost select(...) call chain."""
        if not (self._current_async_func and self._func_needs_fix):
            return updated_node

        if not _is_select_chain(original_node):
            return updated_node

        # Ensure we only patch the outermost Call in a method chain
        parent = self.get_metadata(ParentNodeProvider, original_node)
        if isinstance(parent, cst.Attribute) and parent.value is original_node:
            return updated_node

        # Do not append if already ending with with_for_update
        if (
            isinstance(original_node.func, cst.Attribute)
            and original_node.func.attr.value == "with_for_update"
        ):
            return updated_node

        # Append .with_for_update()
        return cst.Call(
            func=cst.Attribute(
                value=updated_node,
                attr=cst.Name("with_for_update"),
            ),
            args=[],
        )


class IdempotencyHeaderTransformer(cst.CSTTransformer):
    """LibCST transformer that appends idempotency_key parameter to POST route handlers."""

    def __init__(self, target_functions: set[str] | None = None) -> None:
        super().__init__()
        self.target_functions = target_functions

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        """Append idempotency_key: str = Header(..., alias='Idempotency-Key') to parameters."""
        if original_node.asynchronous is None:
            return updated_node

        if (
            self.target_functions is not None
            and original_node.name.value not in self.target_functions
        ):
            return updated_node

        parsed_fn = cst.parse_statement(
            'def _(idempotency_key: str = Header(..., alias="Idempotency-Key")): pass'
        )
        assert isinstance(parsed_fn, cst.FunctionDef)
        new_param = parsed_fn.params.params[0]

        old_params = list(updated_node.params.params)
        if old_params:
            last = old_params[-1]
            if isinstance(last.comma, cst.Comma) and isinstance(
                last.comma.whitespace_after, cst.ParenthesizedWhitespace
            ):
                pw = last.comma.whitespace_after
                updated_prev_comma = cst.Comma(
                    whitespace_after=cst.ParenthesizedWhitespace(
                        first_line=pw.first_line,
                        empty_lines=pw.empty_lines,
                        indent=pw.indent,
                        last_line=cst.SimpleWhitespace("    "),
                    )
                )
                old_params[-1] = last.with_changes(comma=updated_prev_comma)
                new_param = new_param.with_changes(comma=last.comma)
                new_params = tuple(old_params + [new_param])
            else:
                old_params[-1] = last.with_changes(
                    comma=cst.Comma(whitespace_after=cst.SimpleWhitespace(" "))
                )
                new_params = tuple(old_params + [new_param])
        else:
            new_params = (new_param,)

        return updated_node.with_changes(params=updated_node.params.with_changes(params=new_params))


class IntegrityErrorGuardTransformer(cst.CSTTransformer):
    """LibCST transformer wrapping await session.commit() in try/except IntegrityError."""

    def __init__(self, target_functions: set[str] | None = None) -> None:
        super().__init__()
        self.target_functions = target_functions
        self._current_func: str | None = None

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        """Inspect function entry."""
        if node.asynchronous is not None and (
            self.target_functions is None or node.name.value in self.target_functions
        ):
            self._current_func = node.name.value
        return True

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        """Clear state on function exit."""
        if original_node.asynchronous is not None and self._current_func == original_node.name.value:
            self._current_func = None
        return updated_node

    def leave_SimpleStatementLine(
        self, original_node: cst.SimpleStatementLine, updated_node: cst.SimpleStatementLine
    ) -> cst.BaseStatement:
        """Replace await session.commit() with try...except IntegrityError."""
        if not self._current_func:
            return updated_node

        session_name: str | None = None
        for expr in original_node.body:
            if isinstance(expr, cst.Expr) and isinstance(expr.value, cst.Await):
                call = expr.value.expression
                if (
                    isinstance(call, cst.Call)
                    and isinstance(call.func, cst.Attribute)
                    and call.func.attr.value == "commit"
                ):
                    session_name = _get_module_name(call.func.value) or "db"
                    break

        if session_name:
            try_stmt = cst.parse_statement(
                f"""try:
    await {session_name}.commit()
except IntegrityError:
    await {session_name}.rollback()
    raise HTTPException(status_code=409, detail="Concurrent conflict: resource already exists")
"""
            )
            return try_stmt

        return updated_node


def apply_all_fixes(source_code: str, rules: set[str] | None = None) -> str:
    """Apply auto-patch fixes for specified concurrency and idempotency rules."""
    selected_rules = rules if rules is not None else {"CG-001", "CG-002", "CG-004"}
    current_code = source_code
    findings = scan_source_code(current_code)

    # 1. CG-001: WithForUpdateTransformer
    if "CG-001" in selected_rules:
        cg001_targets = {f.function_name for f in findings if f.rule_id == "CG-001"}
        if cg001_targets:
            tree = cst.parse_module(current_code)
            wrapper = MetadataWrapper(tree)
            current_code = wrapper.visit(
                WithForUpdateTransformer(target_functions=cg001_targets)
            ).code
            findings = scan_source_code(current_code)

    # 2. CG-002: IdempotencyHeaderTransformer
    if "CG-002" in selected_rules:
        cg002_targets = {f.function_name for f in findings if f.rule_id == "CG-002"}
        if cg002_targets:
            tree = cst.parse_module(current_code)
            tree = tree.visit(IdempotencyHeaderTransformer(target_functions=cg002_targets))
            tree = _ensure_import(tree, "fastapi", "Header")
            current_code = tree.code
            findings = scan_source_code(current_code)

    # 3. CG-004: IntegrityErrorGuardTransformer
    if "CG-004" in selected_rules:
        cg004_targets = {f.function_name for f in findings if f.rule_id == "CG-004"}
        if cg004_targets:
            tree = cst.parse_module(current_code)
            tree = tree.visit(IntegrityErrorGuardTransformer(target_functions=cg004_targets))
            tree = _ensure_import(tree, "sqlalchemy.exc", "IntegrityError")
            tree = _ensure_import(tree, "fastapi", "HTTPException")
            current_code = tree.code

    return current_code


def apply_with_for_update_fix(source_code: str) -> str:
    """Parse source code, apply WithForUpdateTransformer, and return modified code."""
    return apply_all_fixes(source_code, rules={"CG-001"})

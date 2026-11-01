"""Deterministic LibCST auto-patcher for concurrency locking."""

from __future__ import annotations

import libcst as cst
from libcst.metadata import MetadataWrapper, ParentNodeProvider


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


class WithForUpdateTransformer(cst.CSTTransformer):
    """LibCST transformer that appends .with_for_update() to unlocked select statements."""

    METADATA_DEPENDENCIES = (ParentNodeProvider,)

    def __init__(self) -> None:
        super().__init__()
        self._current_async_func: cst.FunctionDef | None = None
        self._func_needs_fix: bool = False

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool:
        """Inspect async function entry."""
        if node.asynchronous is not None:
            self._current_async_func = node
            self._func_needs_fix = not _func_has_with_for_update(node)
        return True

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        """Clear state on async function exit."""
        if original_node.asynchronous is not None:
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


def apply_with_for_update_fix(source_code: str) -> str:
    """Parse source code, apply WithForUpdateTransformer, and return modified code."""
    module = cst.parse_module(source_code)
    wrapper = MetadataWrapper(module)
    transformed_module = wrapper.visit(WithForUpdateTransformer())
    return transformed_module.code

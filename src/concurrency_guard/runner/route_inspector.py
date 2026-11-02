"""Dynamic FastAPI route discovery and AST-based mutation analysis."""

from __future__ import annotations

import ast
import sys
from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Optional, get_type_hints

from pydantic import BaseModel


@dataclass
class DiscoveredTarget:
    """A discovered FastAPI route target with extracted metadata."""

    path: str
    method: str
    function_name: str
    endpoint_fn: Callable[..., Any]
    pydantic_model: Optional[type[BaseModel]]
    mutated_attribute: Optional[str]
    uses_for_update: bool


def _extract_mutated_attribute(func_ast: ast.AsyncFunctionDef) -> Optional[str]:
    """Extract the attribute name mutated via AugAssign or BinOp Assign in an async function."""
    for node in ast.walk(func_ast):
        # Nested function definitions should not be inspected
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not func_ast:
            continue
        # AugAssign: e.g. wallet.balance -= amount
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Attribute):
            return node.target.attr
        # Assign with BinOp: e.g. wallet.balance = wallet.balance - amount
        if isinstance(node, ast.Assign) and node.targets:
            target = node.targets[0]
            if isinstance(target, ast.Attribute) and isinstance(node.value, ast.BinOp):
                return target.attr
    return None


def _check_uses_for_update(func_ast: ast.AsyncFunctionDef) -> bool:
    """Check if the function AST contains a .with_for_update() call."""
    for node in ast.walk(func_ast):
        if isinstance(node, ast.Attribute) and node.attr == "with_for_update":
            return True
    return False


def _build_function_map(source_code: str) -> dict[str, ast.AsyncFunctionDef]:
    """Build a mapping of function name -> AST node for async function definitions."""
    tree = ast.parse(source_code)
    result: dict[str, ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            result[node.name] = node
    return result


def _extract_pydantic_model(endpoint_fn: Callable[..., Any]) -> Optional[type[BaseModel]]:
    """Extract the Pydantic BaseModel type annotation from an endpoint's parameters.

    Uses get_type_hints() to resolve forward references that result from
    'from __future__ import annotations' in the endpoint's module.
    """
    # Resolve annotations in the context of the endpoint's module (handles PEP 563 strings)
    module_globals: dict[str, Any] = {}
    module_name = getattr(endpoint_fn, "__module__", None)
    if module_name and module_name in sys.modules:
        module_globals = vars(sys.modules[module_name])

    try:
        hints = get_type_hints(endpoint_fn, globalns=module_globals)
    except Exception:  # noqa: BLE001
        hints = {}

    for param_name, annotation in hints.items():
        if param_name == "return":
            continue
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            return annotation
    return None


def discover_fastapi_targets(
    module: ModuleType,
    source_code: str,
    target_function: Optional[str] = None,
) -> list[DiscoveredTarget]:
    """Discover POST/PUT/PATCH FastAPI routes and extract mutation metadata via AST."""
    # Locate the FastAPI app in the module
    target_app: Any = None
    for attr_name in dir(module):
        obj = getattr(module, attr_name, None)
        if obj is not None and type(obj).__name__ == "FastAPI":
            target_app = obj
            break

    if target_app is None:
        return []

    func_map = _build_function_map(source_code)
    targets: list[DiscoveredTarget] = []

    for route in getattr(target_app, "routes", []):
        # Only process APIRoute instances
        if type(route).__name__ != "APIRoute":
            continue

        methods: set[str] = getattr(route, "methods", set()) or set()
        mutating_methods = methods & {"POST", "PUT", "PATCH"}
        if not mutating_methods:
            continue

        endpoint_fn: Optional[Callable[..., Any]] = getattr(route, "endpoint", None)
        if endpoint_fn is None:
            continue

        fn_name = endpoint_fn.__name__
        if target_function is not None and fn_name != target_function:
            continue

        func_ast = func_map.get(fn_name)
        mutated_attr: Optional[str] = None
        uses_for_update = False

        if func_ast is not None:
            mutated_attr = _extract_mutated_attribute(func_ast)
            uses_for_update = _check_uses_for_update(func_ast)

        pydantic_model = _extract_pydantic_model(endpoint_fn)
        route_path: str = getattr(route, "path", "")
        method = min(mutating_methods)  # Pick primary method

        targets.append(
            DiscoveredTarget(
                path=route_path,
                method=method,
                function_name=fn_name,
                endpoint_fn=endpoint_fn,
                pydantic_model=pydantic_model,
                mutated_attribute=mutated_attr,
                uses_for_update=uses_for_update,
            )
        )

    return targets

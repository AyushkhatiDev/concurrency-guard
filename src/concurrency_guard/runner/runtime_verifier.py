"""Headless barrier verification for arbitrary Python callables.

Unlike the HTTP verifier, this runner imports a user-selected source file into
an isolated module namespace and observes in-memory mutable state directly.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import inspect
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, TypedDict

from concurrency_guard.runner.barrier_engine import Barrier


class HeadlessVerificationResult(TypedDict):
    """Observed state and invariant outcome from a headless stress run."""

    function_name: str
    workers: int
    execution_mode: str
    state_name: str
    key: str
    initial_value: int
    expected_value: int
    actual_value: int
    completed_workers: int
    worker_errors: int
    invariant_violated: bool


def load_function(file_path: Path, function_name: str) -> tuple[ModuleType, Callable[..., Any]]:
    """Import ``function_name`` from a source file under an isolated module name."""
    module_id = hashlib.sha256(str(file_path.resolve()).encode()).hexdigest()[:12]
    spec = importlib.util.spec_from_file_location(f"cguard_target_{module_id}", file_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Unable to create an import specification for {file_path}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = getattr(module, function_name, None)
    if target is None or not callable(target):
        raise ValueError(f"Function '{function_name}' was not found in {file_path}.")
    return module, target


def _select_state(module: ModuleType) -> tuple[str, dict[str, Any]]:
    for name, value in vars(module).items():
        if not name.startswith("_") and isinstance(value, dict):
            return name, value
    return "synthesized_state", {}


def _synthesize_arguments(target: Callable[..., Any], state: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    """Supply deterministic primitives and the observed shared dictionary by name."""
    args: list[Any] = []
    kwargs: dict[str, Any] = {}
    for parameter in inspect.signature(target).parameters.values():
        if parameter.kind in {parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD}:
            continue
        if parameter.default is not inspect.Parameter.empty:
            continue
        lower = parameter.name.lower()
        if any(token in lower for token in ("state", "dict", "cache", "mapping", "data", "store")):
            value: Any = state
        elif "key" in lower or "name" in lower:
            value = "count"
        elif any(token in lower for token in ("amount", "value", "increment", "delta", "count")):
            value = 1
        else:
            value = SimpleNamespace()
        if parameter.kind is parameter.KEYWORD_ONLY:
            kwargs[parameter.name] = value
        else:
            args.append(value)
    return args, kwargs


def _numeric_state(state: dict[str, Any]) -> tuple[str, int]:
    for key, value in state.items():
        if isinstance(value, int) and not isinstance(value, bool):
            return str(key), value
    return "count", 0


async def _verify_async(
    target: Callable[..., Any], args: list[Any], kwargs: dict[str, Any], workers: int
) -> tuple[int, int]:
    barrier = Barrier(workers)

    async def worker() -> bool:
        await barrier.wait()
        try:
            await target(*args, **kwargs)
            return True
        except Exception:  # noqa: BLE001
            return False

    results = await asyncio.gather(*(worker() for _ in range(workers)))
    return sum(results), workers - sum(results)


def _verify_sync(
    target: Callable[..., Any], args: list[Any], kwargs: dict[str, Any], workers: int
) -> tuple[int, int]:
    barrier = threading.Barrier(workers)

    def worker() -> bool:
        try:
            barrier.wait()
            target(*args, **kwargs)
            return True
        except Exception:  # noqa: BLE001
            return False

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda _: worker(), range(workers)))
    return sum(results), workers - sum(results)


def verify_function(file_path: Path, function_name: str, workers: int = 20) -> HeadlessVerificationResult:
    """Barrier-stress a raw callable and verify a numeric shared-dict invariant."""
    if workers < 2:
        raise ValueError("Headless verification requires at least two workers.")
    module, target = load_function(file_path, function_name)
    state_name, state = _select_state(module)
    args, kwargs = _synthesize_arguments(target, state)
    key, initial_value = _numeric_state(state)

    if inspect.iscoroutinefunction(target):
        completed, errors = asyncio.run(_verify_async(target, args, kwargs, workers))
        mode = "asyncio"
    else:
        completed, errors = _verify_sync(target, args, kwargs, workers)
        mode = "threading"

    actual_value = state.get(key, 0)
    if not isinstance(actual_value, int) or isinstance(actual_value, bool):
        actual_value = 0
    expected_value = initial_value + completed
    return HeadlessVerificationResult(
        function_name=function_name,
        workers=workers,
        execution_mode=mode,
        state_name=state_name,
        key=key,
        initial_value=initial_value,
        expected_value=expected_value,
        actual_value=actual_value,
        completed_workers=completed,
        worker_errors=errors,
        invariant_violated=completed > 0 and actual_value != expected_value,
    )

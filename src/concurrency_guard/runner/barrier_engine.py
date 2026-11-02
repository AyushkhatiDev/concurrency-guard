"""Concurrency stress verification engine using asyncio.Barrier."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any, Optional, TypedDict

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

if sys.version_info >= (3, 11):
    from asyncio import Barrier
else:
    class Barrier:
        """Lightweight fallback for asyncio.Barrier on Python < 3.11."""

        def __init__(self, parties: int) -> None:
            self._parties = parties
            self._count = 0
            self._cond = asyncio.Condition()

        async def wait(self) -> int:
            async with self._cond:
                index = self._count
                self._count += 1
                if self._count == self._parties:
                    self._cond.notify_all()
                else:
                    await self._cond.wait()
                return index

_row_lock = asyncio.Lock()
_installed_lock = False


def enable_for_update_locking() -> None:
    """Simulate row-level locking for SQLite in-memory tests when with_for_update is used."""
    global _installed_lock
    if _installed_lock:
        return
    _installed_lock = True

    orig_execute = AsyncSession.execute
    orig_commit = AsyncSession.commit
    orig_rollback = AsyncSession.rollback
    orig_close = AsyncSession.close

    async def _hooked_execute(
        self: AsyncSession, statement: Any, *args: Any, **kwargs: Any
    ) -> Any:
        if (
            getattr(statement, "_for_update_arg", None) is not None
            and not getattr(self, "_holding_for_update_lock", False)
        ):
            await _row_lock.acquire()
            setattr(self, "_holding_for_update_lock", True)  # noqa: B010
        return await orig_execute(self, statement, *args, **kwargs)

    async def _release(self: AsyncSession) -> None:
        if getattr(self, "_holding_for_update_lock", False):
            setattr(self, "_holding_for_update_lock", False)  # noqa: B010
            if _row_lock.locked():
                _row_lock.release()

    async def _hooked_commit(self: AsyncSession, *args: Any, **kwargs: Any) -> Any:
        try:
            return await orig_commit(self, *args, **kwargs)
        finally:
            await _release(self)

    async def _hooked_rollback(self: AsyncSession, *args: Any, **kwargs: Any) -> Any:
        try:
            return await orig_rollback(self, *args, **kwargs)
        finally:
            await _release(self)

    async def _hooked_close(self: AsyncSession, *args: Any, **kwargs: Any) -> Any:
        try:
            return await orig_close(self, *args, **kwargs)
        finally:
            await _release(self)

    AsyncSession.execute = _hooked_execute  # type: ignore[method-assign]
    AsyncSession.commit = _hooked_commit  # type: ignore[method-assign]
    AsyncSession.rollback = _hooked_rollback  # type: ignore[method-assign]
    AsyncSession.close = _hooked_close  # type: ignore[method-assign]


class BarrierResult(TypedDict):
    """Structured result dictionary returned by barrier stress runner."""

    workers: int
    initial_balance: int
    success_count: int
    final_balance: int
    invariant_violated: bool


async def run_barrier_test(
    app: Optional[Any] = None,
    endpoint: str = "/wallet/withdraw",
    handler: Optional[Callable[[], Coroutine[Any, Any, bool]]] = None,
    workers: int = 20,
    initial_balance: int = 50,
    withdraw_amount: int = 50,
    user_id: int = 1,
    headers: Optional[dict[str, str]] = None,
    engine: Optional[Any] = None,
    session_factory: Optional[Any] = None,
    wallet_model: Optional[Any] = None,
    base_metadata: Optional[Any] = None,
) -> BarrierResult:
    """Stress test a FastAPI endpoint or async handler using an asyncio.Barrier."""
    enable_for_update_locking()

    # Seed isolated database state if database objects provided
    if engine is not None and session_factory is not None and wallet_model is not None:
        if base_metadata is not None:
            async with engine.begin() as conn:
                await conn.run_sync(base_metadata.create_all)

        async with session_factory() as session:
            await session.execute(wallet_model.__table__.delete())
            session.add(wallet_model(user_id=user_id, balance=float(initial_balance)))
            await session.commit()

    barrier = Barrier(workers)

    if handler is not None:
        async def handler_worker() -> bool:
            await barrier.wait()
            try:
                res = await handler()
                return bool(res)
            except Exception:  # noqa: BLE001
                return False

        gathered = await asyncio.gather(
            *(handler_worker() for _ in range(workers)),
            return_exceptions=True,
        )
        success_count = sum(1 for r in gathered if r is True)
    elif app is not None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            async def http_worker(i: int) -> bool:
                await barrier.wait()
                req_headers = dict(headers or {})
                if "Idempotency-Key" not in req_headers:
                    req_headers["Idempotency-Key"] = f"barrier-key-{i}"

                try:
                    resp = await client.post(
                        endpoint,
                        json={"user_id": user_id, "amount": float(withdraw_amount)},
                        headers=req_headers,
                    )
                    return resp.status_code == 200
                except Exception:  # noqa: BLE001
                    return False

            gathered = await asyncio.gather(
                *(http_worker(i) for i in range(workers)),
                return_exceptions=True,
            )
            success_count = sum(1 for r in gathered if r is True)
    else:
        raise ValueError("Either 'app' or 'handler' must be provided to run_barrier_test.")

    # Calculate final balance
    if session_factory is not None and wallet_model is not None:
        async with session_factory() as session:
            row = (
                await session.execute(
                    select(wallet_model).where(wallet_model.user_id == user_id)
                )
            ).scalar_one_or_none()
            if row is not None and success_count <= 1:
                final_balance = int(row.balance)
            else:
                # If multiple withdrawals succeeded, effective account balance drops below zero
                final_balance = initial_balance - (success_count * withdraw_amount)
    else:
        final_balance = initial_balance - (success_count * withdraw_amount)

    invariant_violated = (final_balance < 0) or (success_count > 1)

    return BarrierResult(
        workers=workers,
        initial_balance=initial_balance,
        success_count=success_count,
        final_balance=final_balance,
        invariant_violated=invariant_violated,
    )


class DynamicBarrierResult(TypedDict):
    """Result from a dynamically-discovered barrier verification run."""

    endpoint_path: str
    function_name: str
    mutated_field: str
    workers: int
    initial_balance: int
    success_count: int
    final_balance: int
    invariant_violated: bool
    synthesized_payload: dict[str, Any]


async def _run_dynamic_single_target(
    target_app: Any,
    endpoint_path: str,
    function_name: str,
    mutated_field: str,
    payload: dict[str, Any],
    workers: int,
    initial_quota: int,
    engine: Any,
    session_factory: Any,
    model_class: Any,
    base_metadata: Any,
    id_field_name: str,
    id_value: int,
) -> DynamicBarrierResult:
    """Run a barrier stress test against a single dynamically discovered target."""
    enable_for_update_locking()

    # Seed database state
    if base_metadata is not None:
        async with engine.begin() as conn:
            await conn.run_sync(base_metadata.create_all)

    async with session_factory() as session:
        await session.execute(model_class.__table__.delete())
        seed_kwargs: dict[str, Any] = {mutated_field: initial_quota}
        seed_kwargs[id_field_name] = id_value
        # Add a default sku if the model has a sku column
        table_cols = {c.name for c in model_class.__table__.columns}
        if "sku" in table_cols:
            seed_kwargs["sku"] = "TEST-SKU-001"
        session.add(model_class(**seed_kwargs))
        await session.commit()

    barrier = Barrier(workers)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=target_app),
        base_url="http://test",
    ) as client:

        async def worker(i: int) -> bool:
            await barrier.wait()
            req_headers: dict[str, str] = {"Idempotency-Key": f"dyn-barrier-{i}"}
            try:
                resp = await client.post(
                    endpoint_path,
                    json=payload,
                    headers=req_headers,
                )
                return resp.status_code == 200
            except Exception:  # noqa: BLE001
                return False

        gathered = await asyncio.gather(
            *(worker(i) for i in range(workers)),
            return_exceptions=True,
        )
        success_count = sum(1 for r in gathered if r is True)

    # Read final state
    async with session_factory() as session:
        id_col = getattr(model_class, id_field_name)
        row = (
            await session.execute(select(model_class).where(id_col == id_value))
        ).scalar_one_or_none()
        if row is not None and success_count <= 1:
            final_balance = int(getattr(row, mutated_field))
        else:
            amount = payload.get("amount", payload.get("quantity", initial_quota))
            final_balance = initial_quota - (success_count * int(amount))

    invariant_violated = (final_balance < 0) or (success_count > 1)

    return DynamicBarrierResult(
        endpoint_path=endpoint_path,
        function_name=function_name,
        mutated_field=mutated_field,
        workers=workers,
        initial_balance=initial_quota,
        success_count=success_count,
        final_balance=final_balance,
        invariant_violated=invariant_violated,
        synthesized_payload=payload,
    )


def _find_sqlalchemy_model_for_field(
    module: Any, mutated_field: str
) -> Optional[tuple[Any, str, Any, Any, Any]]:
    """Find the SQLAlchemy model that has the mutated field, its ID field, engine, and session."""
    from sqlalchemy.orm import DeclarativeBase

    engine: Any = getattr(module, "engine", None)
    session_factory: Any = getattr(
        module, "async_session", getattr(module, "AsyncSessionLocal", None)
    )
    if engine is None or session_factory is None:
        return None

    # Find the model class that has the mutated_field column
    model_class: Any = None
    id_field_name: str = "id"
    for attr_name in dir(module):
        obj = getattr(module, attr_name, None)
        if (
            isinstance(obj, type)
            and hasattr(obj, "__tablename__")
            and hasattr(obj, mutated_field)
        ):
            model_class = obj
            # Find a likely ID field
            tbl: Any = getattr(obj, "__table__", None)
            table_cols: set[str] = {c.name for c in tbl.columns} if tbl is not None else set()
            for candidate in ("item_id", "user_id", "account_id", "product_id"):
                if candidate in table_cols:
                    id_field_name = candidate
                    break
            break

    if model_class is None:
        return None

    # Find the base metadata
    base_meta: Any = None
    for attr_name in dir(module):
        obj = getattr(module, attr_name, None)
        if (
            isinstance(obj, type)
            and issubclass(obj, DeclarativeBase)
            and obj is not DeclarativeBase
            and hasattr(obj, "metadata")
        ):
            base_meta = obj.metadata
            break

    return model_class, id_field_name, engine, session_factory, base_meta


async def run_dynamic_barrier_verification(
    file_path: Path,
    function_name: Optional[str] = None,
    workers: int = 20,
    initial_quota: int = 50,
) -> list[DynamicBarrierResult]:
    """Dynamically discover, seed, and stress-test FastAPI routes in any target file."""
    from concurrency_guard.runner.route_inspector import discover_fastapi_targets
    from concurrency_guard.runner.schema_synthesizer import synthesize_request_payload

    module_name = f"cguard_dyn_{file_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        return []

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    source_code = file_path.read_text(encoding="utf-8")
    targets = discover_fastapi_targets(module, source_code, target_function=function_name)

    results: list[DynamicBarrierResult] = []

    for target in targets:
        if target.mutated_attribute is None:
            continue

        payload = synthesize_request_payload(target.pydantic_model, initial_quota=initial_quota)

        model_info = _find_sqlalchemy_model_for_field(module, target.mutated_attribute)
        if model_info is None:
            continue

        model_class, id_field_name, db_engine, session_factory, base_meta = model_info

        # Find the FastAPI app for ASGI transport
        target_app: Any = None
        for attr_name in dir(module):
            obj = getattr(module, attr_name, None)
            if obj is not None and type(obj).__name__ == "FastAPI":
                target_app = obj
                break

        if target_app is None:
            continue

        result = await _run_dynamic_single_target(
            target_app=target_app,
            endpoint_path=target.path,
            function_name=target.function_name,
            mutated_field=target.mutated_attribute,
            payload=payload,
            workers=workers,
            initial_quota=initial_quota,
            engine=db_engine,
            session_factory=session_factory,
            model_class=model_class,
            base_metadata=base_meta,
            id_field_name=id_field_name,
            id_value=payload.get(id_field_name, payload.get("user_id", 1)),
        )
        results.append(result)

    return results

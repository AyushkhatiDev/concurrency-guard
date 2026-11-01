"""Concurrency stress verification engine using asyncio.Barrier."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable, Coroutine
from typing import Any, TypedDict

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
    app: Any | None = None,
    endpoint: str = "/wallet/withdraw",
    handler: Callable[[], Coroutine[Any, Any, bool]] | None = None,
    workers: int = 20,
    initial_balance: int = 50,
    withdraw_amount: int = 50,
    user_id: int = 1,
    headers: dict[str, str] | None = None,
    engine: Any | None = None,
    session_factory: Any | None = None,
    wallet_model: Any | None = None,
    base_metadata: Any | None = None,
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

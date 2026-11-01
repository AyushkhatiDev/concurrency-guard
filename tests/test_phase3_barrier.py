"""Unit tests for Phase 3 runtime barrier concurrency verification engine."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import Float, Integer, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from concurrency_guard.runner.barrier_engine import run_barrier_test
from examples.vulnerable_wallet import (
    Base as WalletBase,
)
from examples.vulnerable_wallet import (
    Wallet,
)
from examples.vulnerable_wallet import (
    app as wallet_app,
)
from examples.vulnerable_wallet import (
    async_session as wallet_session,
)
from examples.vulnerable_wallet import (
    engine as wallet_engine,
)


class DummyBase(DeclarativeBase):
    pass


class DummyWallet(DummyBase):
    __tablename__ = "dummy_wallets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, unique=True)
    balance: Mapped[float] = mapped_column(Float)


@pytest.fixture
def isolated_db_setup() -> tuple[Any, Any]:
    """Create an isolated test engine and session factory."""
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)
    return test_engine, session_factory


@pytest.mark.asyncio
async def test_unlocked_wallet_violates_invariant(isolated_db_setup: tuple[Any, Any]) -> None:
    """Verifies that an unlocked read-modify-write handler violates the concurrency invariant."""
    test_engine, session_factory = isolated_db_setup

    async with test_engine.begin() as conn:
        await conn.run_sync(DummyBase.metadata.create_all)

    async with session_factory() as session:
        session.add(DummyWallet(id=1, user_id=1, balance=50.0))
        await session.commit()

    async def unlocked_handler() -> bool:
        async with session_factory() as session:
            stmt = select(DummyWallet).where(DummyWallet.user_id == 1)
            wallet = (await session.execute(stmt)).scalar_one_or_none()
            if wallet and wallet.balance >= 50.0:
                # Context switch point exposing read-modify-write race
                await asyncio.sleep(0.005)
                wallet.balance -= 50.0
                await session.commit()
                return True
            return False

    result = await run_barrier_test(
        handler=unlocked_handler,
        workers=20,
        initial_balance=50,
        withdraw_amount=50,
    )

    assert result["workers"] == 20
    assert result["initial_balance"] == 50
    assert result["success_count"] > 1
    assert result["final_balance"] < 0
    assert result["invariant_violated"] is True


@pytest.mark.asyncio
async def test_locked_wallet_holds_invariant(isolated_db_setup: tuple[Any, Any]) -> None:
    """Verifies that a locked handler using .with_for_update() holds the concurrency invariant."""
    test_engine, session_factory = isolated_db_setup

    async with test_engine.begin() as conn:
        await conn.run_sync(DummyBase.metadata.create_all)

    async with session_factory() as session:
        session.add(DummyWallet(id=1, user_id=1, balance=50.0))
        await session.commit()

    async def locked_handler() -> bool:
        async with session_factory() as session:
            stmt = select(DummyWallet).where(DummyWallet.user_id == 1).with_for_update()
            wallet = (await session.execute(stmt)).scalar_one_or_none()
            if wallet and wallet.balance >= 50.0:
                await asyncio.sleep(0.005)
                wallet.balance -= 50.0
                await session.commit()
                return True
            return False

    result = await run_barrier_test(
        handler=locked_handler,
        workers=20,
        initial_balance=50,
        withdraw_amount=50,
    )

    assert result["workers"] == 20
    assert result["initial_balance"] == 50
    assert result["success_count"] == 1
    assert result["final_balance"] == 0
    assert result["invariant_violated"] is False


@pytest.mark.asyncio
async def test_fastapi_vulnerable_endpoint_violates_invariant() -> None:
    """Verifies that POST /wallet/withdraw violates the concurrency invariant under barrier stress."""
    result = await run_barrier_test(
        app=wallet_app,
        endpoint="/wallet/withdraw",
        workers=20,
        initial_balance=50,
        withdraw_amount=50,
        engine=wallet_engine,
        session_factory=wallet_session,
        wallet_model=Wallet,
        base_metadata=WalletBase.metadata,
    )

    assert result["workers"] == 20
    assert result["success_count"] > 1
    assert result["invariant_violated"] is True


@pytest.mark.asyncio
async def test_fastapi_safe_endpoint_holds_invariant() -> None:
    """Verifies that POST /wallet/withdraw-safe preserves the concurrency invariant under barrier stress."""
    result = await run_barrier_test(
        app=wallet_app,
        endpoint="/wallet/withdraw-safe",
        workers=20,
        initial_balance=50,
        withdraw_amount=50,
        engine=wallet_engine,
        session_factory=wallet_session,
        wallet_model=Wallet,
        base_metadata=WalletBase.metadata,
        headers={"Idempotency-Key": "test-key"},
    )

    assert result["workers"] == 20
    assert result["success_count"] == 1
    assert result["final_balance"] == 0
    assert result["invariant_violated"] is False

"""Example FastAPI application demonstrating vulnerable and safe wallet withdrawal endpoints."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Union

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import Float, Integer, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


class Wallet(Base):
    __tablename__ = "wallets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    balance: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)


class WithdrawRequest(BaseModel):
    user_id: int
    amount: float = Field(..., gt=0)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


app = FastAPI(title="Wallet Service")


@app.post("/wallet/withdraw")
async def withdraw(
    request: WithdrawRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Union[float, str]]:
    """Vulnerable endpoint: reads wallet balance, modifies it, and commits without row locking."""
    stmt = select(Wallet).where(Wallet.user_id == request.user_id)
    result = await db.execute(stmt)
    wallet = result.scalar_one_or_none()

    if wallet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Wallet not found")

    if wallet.balance < request.amount:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient funds")

    # Race condition: Unlocked Read-Modify-Write
    wallet.balance -= request.amount
    await db.commit()

    return {"status": "success", "new_balance": wallet.balance}


@app.post("/wallet/withdraw-safe")
async def withdraw_safe(
    request: WithdrawRequest,
    db: AsyncSession = Depends(get_db),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
) -> dict[str, Union[float, str]]:
    """Safe endpoint: acquires row-level lock using .with_for_update() to prevent race conditions."""
    stmt = (
        select(Wallet)
        .where(Wallet.user_id == request.user_id)
        .with_for_update()
    )
    result = await db.execute(stmt)
    wallet = result.scalar_one_or_none()

    if wallet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Wallet not found")

    if wallet.balance < request.amount:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient funds")

    wallet.balance -= request.amount
    await db.commit()

    return {"status": "success", "new_balance": wallet.balance}

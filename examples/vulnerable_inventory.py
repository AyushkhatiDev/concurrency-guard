"""Example FastAPI application demonstrating vulnerable and safe inventory reservation endpoints."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Union

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


class InventoryItem(Base):
    __tablename__ = "inventory_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    item_id: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    sku: Mapped[str] = mapped_column(String(100), nullable=False, default="DEFAULT-SKU")
    stock_quantity: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class ReserveStockRequest(BaseModel):
    item_id: int
    quantity: int = Field(..., gt=0)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


app = FastAPI(title="Inventory Service")


@app.post("/inventory/reserve")
async def reserve_stock(
    request: ReserveStockRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Union[int, str]]:
    """Vulnerable endpoint: reads stock, modifies it, and commits without row locking."""
    stmt = select(InventoryItem).where(InventoryItem.item_id == request.item_id)
    result = await db.execute(stmt)
    item = result.scalar_one_or_none()

    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    if item.stock_quantity < request.quantity:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient stock"
        )

    # Race condition: Unlocked Read-Modify-Write
    item.stock_quantity -= request.quantity
    await db.commit()

    return {"status": "reserved", "remaining_stock": item.stock_quantity}


@app.post("/inventory/reserve-safe")
async def reserve_stock_safe(
    request: ReserveStockRequest,
    db: AsyncSession = Depends(get_db),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
) -> dict[str, Union[int, str]]:
    """Safe endpoint: acquires row-level lock using .with_for_update() to prevent race conditions."""
    stmt = (
        select(InventoryItem)
        .where(InventoryItem.item_id == request.item_id)
        .with_for_update()
    )
    result = await db.execute(stmt)
    item = result.scalar_one_or_none()

    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    if item.stock_quantity < request.quantity:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient stock"
        )

    item.stock_quantity -= request.quantity
    await db.commit()

    return {"status": "reserved", "remaining_stock": item.stock_quantity}


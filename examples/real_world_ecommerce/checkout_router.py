"""FastAPI checkout and payment router demonstrating real-world concurrency issues."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from examples.real_world_ecommerce.models import Coupon, Order, OrderItem, WebhookEvent

DATABASE_URL = "sqlite+aiosqlite:///:memory:"
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


router = APIRouter()


class RedeemCouponRequest(BaseModel):
    code: str
    user_id: int


@router.post("/coupons/redeem")
async def redeem_coupon(
    request: RedeemCouponRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str | int]:
    """Redeem coupon using SQLAlchemy 2.0 await db.scalar without row-locking or idempotency."""
    stmt = select(Coupon).where(Coupon.code == request.code)
    coupon = await db.scalar(stmt)

    if coupon is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Coupon not found")

    if coupon.remaining_uses > 0:
        # Race condition: Unlocked Read-Modify-Write via db.scalar (CG-001)
        # Missing Idempotency-Key guard (CG-002)
        coupon.remaining_uses -= 1
        await db.commit()
        return {"status": "redeemed", "remaining": coupon.remaining_uses}

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Coupon exhausted")


@router.get("/orders/with-items")
async def get_orders_with_items(
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Fetch orders and query items in a loop: Async Loop N+1 Query Explode (CG-003)."""
    result = await db.execute(select(Order))
    orders = result.scalars().all()
    orders_data: list[dict[str, Any]] = []

    for order in orders:
        stmt = select(OrderItem).where(OrderItem.order_id == order.id)
        # N+1 query: executes inside loop
        items_result = await db.scalars(stmt)
        items = items_result.all()
        orders_data.append({"order_id": order.id, "items": len(items)})

    return orders_data


class StripeWebhookPayload(BaseModel):
    event_id: str
    event_type: str


@router.post("/webhooks/stripe")
async def handle_stripe_webhook(
    payload: StripeWebhookPayload,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Check-then-act uniqueness race on webhook event ingestion (CG-004)."""
    stmt = select(WebhookEvent).where(WebhookEvent.event_id == payload.event_id)
    existing = await db.scalar(stmt)
    if existing is not None:
        return {"status": "already_processed"}

    event = WebhookEvent(
        event_id=payload.event_id,
        event_type=payload.event_type,
        processed=True,
    )
    db.add(event)
    # Unprotected commit: violates uniqueness under race conditions
    await db.commit()
    return {"status": "processed"}


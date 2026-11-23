"""Celery task demonstrating a repeatable database status assignment."""

from __future__ import annotations

from celery import shared_task
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from examples.real_world_ecommerce.models import Order

sync_engine = create_engine("sqlite:///:memory:")
SyncSessionLocal = sessionmaker(bind=sync_engine, class_=Session)


@shared_task(autoretry_for=(Exception,), max_retries=5)
def process_refund(order_id: int) -> dict[str, str]:
    """Record the refunded status. Repeating this assignment has the same result."""
    session = SyncSessionLocal()
    try:
        order = session.get(Order, order_id)
        if order is not None:
            order.status = "REFUNDED"
            session.commit()
    finally:
        session.close()
    return {"status": "refunded"}


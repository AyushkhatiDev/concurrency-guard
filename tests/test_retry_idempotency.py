"""Retry diagnostics distinguish literal row assignments from repeatable side effects."""
from pathlib import Path

import pytest

from concurrency_guard.scanner.ast_rules import scan_file, scan_source_code

TASK = """
from celery import shared_task
@shared_task(autoretry_for=(Exception,), max_retries=3)
def refund(order_id):
    session = SessionLocal()
    try:
        order = session.get(Order, order_id)
        if order is not None:
            order.status = "REFUNDED"
            session.commit()
    finally:
        session.close()
"""


def retry_rules(source: str) -> set[str]:
    return {f.rule_id for f in scan_source_code(source)} & {"CG-005", "CG-023"}


def test_fixed_status_assignment_and_example() -> None:
    assert not retry_rules(TASK)
    assert not {f.rule_id for f in scan_file(Path("examples/real_world_ecommerce/tasks.py"))} & {"CG-005", "CG-023"}


@pytest.mark.parametrize("operation", [
    "order.status = next_status()",
    "order.refunds += 1",
    "session.add(Refund(order_id=order_id))",
    "requests.post(url, json=payload)",
    "order.tags.append(order_id)",
    "order.status = order.status + '_REFUNDED'",
    "order = load_order(order_id)",
])
def test_nonrepeatable_or_unknown_effects_keep_diagnostics(operation: str) -> None:
    source = TASK.replace('order.status = "REFUNDED"', operation)
    assert retry_rules(source) == {"CG-005", "CG-023"}


def test_acks_late_alone_does_not_hide_retry_effects() -> None:
    source = TASK.replace('order.status = "REFUNDED"', "order.balance -= amount")
    source = source.replace("max_retries=3", "max_retries=3, acks_late=True")
    assert retry_rules(source) == {"CG-005", "CG-023"}


def test_state_dependent_literal_writes_still_warn() -> None:
    source = TASK.replace('order.status = "REFUNDED"', """if order.status == "PENDING":
                order.status = "REFUNDED"
            else:
                order.status = "PENDING" """)
    assert retry_rules(source) == {"CG-005", "CG-023"}


def test_repeating_status_assignment_has_same_database_result() -> None:
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from examples.real_world_ecommerce.models import Base, Order

    engine = create_engine("sqlite://")
    try:
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(Order(id=1, user_id=1, total_amount=10, status="PENDING"))
            session.commit()
        statuses = []
        for _ in range(2):
            with Session(engine) as session:
                order = session.get(Order, 1)
                assert order is not None
                order.status = "REFUNDED"
                session.commit()
            with Session(engine) as session:
                statuses.append(session.scalar(select(Order.status).where(Order.id == 1)))
        assert statuses == ["REFUNDED", "REFUNDED"]
    finally:
        engine.dispose()

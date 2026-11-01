"""Unit tests for Phase 2 AST concurrency scanner rules (CG-002, CG-003, CG-004)."""

from __future__ import annotations

from concurrency_guard.scanner.ast_rules import scan_source_code

# -----------------------------------------------------------------------------
# CG-002: Missing Idempotency Guard on POST Routes
# -----------------------------------------------------------------------------


def test_detects_missing_idempotency_key_on_post_route() -> None:
    """Verifies CG-002 triggers on @app.post route modifying database without idempotency key."""
    code = """
@app.post("/checkout")
async def checkout(request: CheckoutRequest, db: AsyncSession = Depends(get_db)):
    wallet.balance -= request.amount
    await db.commit()
    return {"status": "ok"}
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-002"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CG-002"
    assert finding.function_name == "checkout"
    assert "Idempotency-Key" in finding.suggested_fix_hint


def test_detects_missing_idempotency_key_with_router_post_and_add() -> None:
    """Verifies CG-002 triggers on @router.post executing session.add()."""
    code = """
@router.post("/items")
async def create_item(item: ItemCreate, session: AsyncSession = Depends(get_session)):
    session.add(Item(name=item.name))
    await session.commit()
    return {"status": "created"}
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-002"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-002"
    assert findings[0].function_name == "create_item"


def test_ignores_post_route_with_idempotency_param() -> None:
    """Verifies 0 CG-002 findings when idempotency_key parameter is present."""
    code = """
@app.post("/checkout")
async def checkout(
    request: CheckoutRequest,
    db: AsyncSession = Depends(get_db),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
):
    wallet.balance -= request.amount
    await db.commit()
    return {"status": "ok"}
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-002"]
    assert len(findings) == 0


def test_ignores_post_route_with_annotated_idempotency_key() -> None:
    """Verifies 0 CG-002 findings when Header alias includes Idempotency-Key."""
    code = """
@app.post("/checkout")
async def checkout(
    request: CheckoutRequest,
    key: Annotated[str, Header(alias="Idempotency-Key")],
    db: AsyncSession = Depends(get_db),
):
    wallet.balance -= request.amount
    await db.commit()
    return {"status": "ok"}
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-002"]
    assert len(findings) == 0


def test_ignores_get_route_without_idempotency_key() -> None:
    """Verifies CG-002 does NOT trigger on GET routes."""
    code = """
@app.get("/items")
async def list_items(db: AsyncSession = Depends(get_db)):
    await db.commit()
    return []
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-002"]
    assert len(findings) == 0


def test_ignores_post_route_without_db_mutations() -> None:
    """Verifies CG-002 does NOT trigger on POST routes without database mutations."""
    code = """
@app.post("/calculate")
async def calculate(data: CalcInput):
    return {"result": data.x + data.y}
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-002"]
    assert len(findings) == 0


# -----------------------------------------------------------------------------
# CG-003: Async Loop N+1 Query Explode
# -----------------------------------------------------------------------------


def test_detects_query_in_for_loop() -> None:
    """Verifies CG-003 triggers when db.execute is called directly inside a for loop."""
    code = """
async def sync_users(db: AsyncSession, user_ids: list[int]):
    for user_id in user_ids:
        stmt = select(User).where(User.id == user_id)
        res = await db.execute(stmt)
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-003"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CG-003"
    assert finding.function_name == "sync_users"
    assert finding.lineno == 5
    assert "joinedload" in finding.suggested_fix_hint


def test_detects_query_in_async_for_loop() -> None:
    """Verifies CG-003 triggers when session.execute is called directly inside an async for loop."""
    code = """
async def stream_orders(session: AsyncSession, order_stream):
    async for order in order_stream:
        stmt = select(OrderItem).where(OrderItem.order_id == order.id)
        items = await session.execute(stmt)
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-003"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CG-003"
    assert finding.function_name == "stream_orders"
    assert finding.lineno == 5


def test_ignores_batched_query_outside_loop() -> None:
    """Verifies 0 CG-003 findings when queries are batched outside loops."""
    code = """
async def sync_users(db: AsyncSession, user_ids: list[int]):
    stmt = select(User).where(User.id.in_(user_ids))
    result = await db.execute(stmt)
    for user in result.scalars():
        print(user.name)
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-003"]
    assert len(findings) == 0


# -----------------------------------------------------------------------------
# CG-004: Check-Then-Act Uniqueness Race
# -----------------------------------------------------------------------------


def test_detects_check_then_act_uniqueness_race() -> None:
    """Verifies CG-004 triggers when select existence check is followed by add and commit without try-except."""
    code = """
async def register(db: AsyncSession, email: str):
    stmt = select(User).where(User.email == email)
    existing = await db.scalar(stmt)
    if existing:
        raise HTTPException(status_code=400, detail="User exists")
    user = User(email=email)
    db.add(user)
    await db.commit()
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-004"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CG-004"
    assert finding.function_name == "register"
    assert finding.lineno == 3
    assert "IntegrityError" in finding.suggested_fix_hint


def test_ignores_handled_integrity_error() -> None:
    """Verifies 0 CG-004 findings when commit is wrapped in try-except catching IntegrityError."""
    code = """
async def register(db: AsyncSession, email: str):
    stmt = select(User).where(User.email == email)
    existing = await db.scalar(stmt)
    if existing:
        raise HTTPException(status_code=400, detail="User exists")
    user = User(email=email)
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="User already registered")
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-004"]
    assert len(findings) == 0


def test_ignores_handled_attribute_integrity_error() -> None:
    """Verifies 0 CG-004 findings when catching sqlalchemy.exc.IntegrityError."""
    code = """
async def register(db: AsyncSession, email: str):
    stmt = select(User).where(User.email == email)
    existing = await db.scalar(stmt)
    if existing:
        raise HTTPException(status_code=400, detail="User exists")
    user = User(email=email)
    db.add(user)
    try:
        await db.commit()
    except (sqlalchemy.exc.IntegrityError, ValueError):
        raise HTTPException(status_code=409, detail="User already registered")
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-004"]
    assert len(findings) == 0


def test_ignores_add_without_select_check() -> None:
    """Verifies 0 CG-004 findings when adding an entity without a preceding select check."""
    code = """
async def log_event(db: AsyncSession, message: str):
    log = AuditLog(message=message)
    db.add(log)
    await db.commit()
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-004"]
    assert len(findings) == 0

"""Tests for distributed task queue and transaction boundary race detection (CG-022, CG-023, CG-024)
and LibCST auto-remediation.
"""

from __future__ import annotations

from concurrency_guard.patcher.cst_fixer import apply_all_fixes, apply_all_fixes_with_report
from concurrency_guard.sarif import RULE_REGISTRY, findings_to_sarif
from concurrency_guard.scanner.ast_rules import ASTFinding, scan_source_code


def test_cg_022_sqlalchemy_premature_dispatch() -> None:
    """Test 1: SQLAlchemy premature task dispatch before commit flags CG-022,
    and moving dispatch after commit resolves to 0 findings.
    """
    vulnerable_code = """
async def checkout(db, order):
    db.add(order)
    send_receipt.delay(order.id)
    await db.commit()
"""
    findings = [f for f in scan_source_code(vulnerable_code) if f.rule_id == "CG-022"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-022"
    assert "Premature background task dispatch before commit" in findings[0].message
    assert findings[0].lineno == 4

    safe_code = """
async def checkout(db, order):
    db.add(order)
    await db.commit()
    send_receipt.delay(order.id)
"""
    safe_findings = [f for f in scan_source_code(safe_code) if f.rule_id == "CG-022"]
    assert len(safe_findings) == 0


def test_cg_022_fastapi_background_tasks_premature_dispatch() -> None:
    """FastAPI BackgroundTasks.add_task called before db.commit() flags CG-022."""
    vulnerable_code = """
async def create_user(db, user, background_tasks):
    db.add(user)
    background_tasks.add_task(send_welcome_email, user.id)
    await db.commit()
"""
    findings = [f for f in scan_source_code(vulnerable_code) if f.rule_id == "CG-022"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-022"

    safe_code = """
async def create_user(db, user, background_tasks):
    db.add(user)
    await db.commit()
    background_tasks.add_task(send_welcome_email, user.id)
"""
    assert len([f for f in scan_source_code(safe_code) if f.rule_id == "CG-022"]) == 0


def test_cg_022_django_atomic_and_libcst_auto_fix() -> None:
    """Test 2: task.delay(x) inside with transaction.atomic(): flags CG-022,
    and cguard fix wraps it in transaction.on_commit(lambda: task.delay(x)) with 0 remaining findings.
    """
    vulnerable_code = """from django.db import transaction

def place_order(order_id):
    with transaction.atomic():
        order = Order.objects.select_for_update().get(id=order_id)
        order.status = "placed"
        order.save()
        send_confirmation.delay(order.id)
"""
    findings = [f for f in scan_source_code(vulnerable_code) if f.rule_id == "CG-022"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-022"
    assert "Premature task dispatch inside Django transaction.atomic()" in findings[0].message
    assert findings[0].lineno == 8

    # Apply auto-fix
    patch_result = apply_all_fixes_with_report(vulnerable_code, rules={"CG-022"})
    assert patch_result.modified is True
    assert "transaction.on_commit(lambda: send_confirmation.delay(order.id))" in patch_result.code

    # Verify 0 remaining findings in patched code
    post_findings = [f for f in scan_source_code(patch_result.code) if f.rule_id == "CG-022"]
    assert len(post_findings) == 0

    # Test idempotency: re-running fix on already patched code produces identical code
    re_patched = apply_all_fixes(patch_result.code, rules={"CG-022"})
    assert re_patched == patch_result.code


def test_cg_022_django_decorator_and_on_commit_sanitizer() -> None:
    """@transaction.atomic decorated function flags premature dispatch unless wrapped in on_commit."""
    vulnerable_code = """from django.db import transaction

@transaction.atomic
def update_profile(user_id):
    user = User.objects.get(id=user_id)
    user.save()
    sync_profile.apply_async(args=[user.id])
"""
    findings = [f for f in scan_source_code(vulnerable_code) if f.rule_id == "CG-022"]
    assert len(findings) == 1

    safe_code = """from django.db import transaction

@transaction.atomic
def update_profile(user_id):
    user = User.objects.get(id=user_id)
    user.save()
    transaction.on_commit(lambda: sync_profile.apply_async(args=[user.id]))
"""
    assert len([f for f in scan_source_code(safe_code) if f.rule_id == "CG-022"]) == 0


def test_cg_023_non_idempotent_retryable_celery_task() -> None:
    """Test 3: @shared_task(acks_late=True, autoretry_for=(Exception,)) mutating wallet.balance
    and committing without a lock flags CG-023. Adding with redis.lock(...) or .with_for_update() -> 0 findings.
    """
    vulnerable_code = """from celery import shared_task

@shared_task(acks_late=True, autoretry_for=(Exception,))
def process_payout(wallet_id, amount):
    wallet = Wallet.get(wallet_id)
    wallet.balance -= amount
    wallet.save()
"""
    findings = [f for f in scan_source_code(vulnerable_code) if f.rule_id == "CG-023"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-023"
    assert "Non-idempotent retryable worker task" in findings[0].message

    # Sanitizer 1: Protected by redis distributed lock
    safe_with_redis = """from celery import shared_task

@shared_task(acks_late=True, autoretry_for=(Exception,))
def process_payout(wallet_id, amount):
    with redis.lock(f"payout:{wallet_id}"):
        wallet = Wallet.get(wallet_id)
        wallet.balance -= amount
        wallet.save()
"""
    assert len([f for f in scan_source_code(safe_with_redis) if f.rule_id == "CG-023"]) == 0

    # Sanitizer 2: Protected by database row lock (.with_for_update())
    safe_with_db_lock = """from celery import shared_task

@shared_task(acks_late=True, autoretry_for=(Exception,))
def process_payout(db, wallet_id, amount):
    wallet = db.execute(select(Wallet).where(Wallet.id == wallet_id).with_for_update()).scalar_one()
    wallet.balance -= amount
    db.commit()
"""
    assert len([f for f in scan_source_code(safe_with_db_lock) if f.rule_id == "CG-023"]) == 0


def test_cg_023_dramatiq_and_integrity_error_sanitizer() -> None:
    """Dramatiq actor performing mutation without lock flags CG-023; IntegrityError handling sanitizes it."""
    vulnerable_code = """import dramatiq

@dramatiq.actor
def create_ledger_entry(account_id, amount):
    entry = LedgerEntry(account_id=account_id, amount=amount)
    db.add(entry)
    db.commit()
"""
    findings = [f for f in scan_source_code(vulnerable_code) if f.rule_id == "CG-023"]
    assert len(findings) == 1

    safe_code = """import dramatiq
from sqlalchemy.exc import IntegrityError

@dramatiq.actor
def create_ledger_entry(account_id, amount):
    entry = LedgerEntry(account_id=account_id, amount=amount)
    db.add(entry)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
"""
    assert len([f for f in scan_source_code(safe_code) if f.rule_id == "CG-023"]) == 0


def test_cg_024_external_http_inside_db_transaction() -> None:
    """Test 4: await httpx.AsyncClient().post(...) or requests.post(...) inside
    async with session.begin(): flags CG-024. Moving HTTP call outside -> 0 findings.
    """
    vulnerable_code = """
async def charge_order(session, order_id, payload):
    async with session.begin():
        await session.execute(update(Order).where(Order.id == order_id).values(status="charging"))
        resp = await httpx.AsyncClient().post("https://api.stripe.com/v1/charges", json=payload)
        await session.execute(update(Order).where(Order.id == order_id).values(status="paid"))
"""
    findings = [f for f in scan_source_code(vulnerable_code) if f.rule_id == "CG-024"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-024"
    assert "External network I/O inside open database transaction" in findings[0].message
    assert findings[0].lineno == 5

    # Safe code: HTTP call performed outside the transaction block
    safe_code = """
async def charge_order(session, order_id, payload):
    resp = await httpx.AsyncClient().post("https://api.stripe.com/v1/charges", json=payload)
    async with session.begin():
        await session.execute(update(Order).where(Order.id == order_id).values(status="paid"))
"""
    assert len([f for f in scan_source_code(safe_code) if f.rule_id == "CG-024"]) == 0


def test_cg_024_requests_post_inside_django_atomic() -> None:
    """requests.post() inside with transaction.atomic(): flags CG-024."""
    vulnerable_code = """from django.db import transaction
import requests

def capture_payment(order_id):
    with transaction.atomic():
        order = Order.objects.select_for_update().get(id=order_id)
        requests.post("https://api.paypal.com/capture", json={"id": order.payment_id})
        order.status = "captured"
        order.save()
"""
    findings = [f for f in scan_source_code(vulnerable_code) if f.rule_id == "CG-024"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-024"

    safe_code = """from django.db import transaction
import requests

def capture_payment(order_id):
    order = Order.objects.get(id=order_id)
    requests.post("https://api.paypal.com/capture", json={"id": order.payment_id})
    with transaction.atomic():
        order = Order.objects.select_for_update().get(id=order_id)
        order.status = "captured"
        order.save()
"""
    assert len([f for f in scan_source_code(safe_code) if f.rule_id == "CG-024"]) == 0


def test_cg_022_024_sarif_metadata_verification() -> None:
    """Test 5: Verify CG-022, CG-023, and CG-024 appear in SARIF report with valid
    CWE tags and severity levels.
    """
    for rule_id in ("CG-022", "CG-023", "CG-024"):
        assert rule_id in RULE_REGISTRY
        rule_meta = RULE_REGISTRY[rule_id]
        assert rule_meta["id"] == rule_id
        assert "shortDescription" in rule_meta
        assert "fullDescription" in rule_meta
        assert "properties" in rule_meta
        tags = rule_meta["properties"]["tags"]
        assert any(t.startswith("cwe-") for t in tags), f"Missing CWE tag for {rule_id}"
        assert "security-severity" in rule_meta["properties"]

    # Verify serialize to SARIF document
    mock_findings = [
        ASTFinding("CG-022", "tasks.py", 10, "checkout", "premature dispatch", "hint"),
        ASTFinding("CG-023", "tasks.py", 20, "payout", "non-idempotent task", "hint"),
        ASTFinding("CG-024", "tasks.py", 30, "charge", "network io in tx", "hint", confidence="MEDIUM"),
    ]
    sarif = findings_to_sarif(mock_findings)
    assert sarif["version"] == "2.1.0"
    driver_rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}

    assert "CG-022" in driver_rules
    assert "cwe-362" in driver_rules["CG-022"]["properties"]["tags"]
    assert driver_rules["CG-022"]["defaultConfiguration"]["level"] == "error"

    assert "CG-023" in driver_rules
    assert "cwe-362" in driver_rules["CG-023"]["properties"]["tags"]
    assert "cwe-662" in driver_rules["CG-023"]["properties"]["tags"]
    assert driver_rules["CG-023"]["defaultConfiguration"]["level"] == "error"

    assert "CG-024" in driver_rules
    assert "cwe-662" in driver_rules["CG-024"]["properties"]["tags"]
    assert driver_rules["CG-024"]["defaultConfiguration"]["level"] == "warning"

    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    rule_results = {r["ruleId"]: r for r in results}
    assert rule_results["CG-022"]["level"] == "error"
    assert rule_results["CG-023"]["level"] == "error"
    assert rule_results["CG-024"]["level"] == "warning"

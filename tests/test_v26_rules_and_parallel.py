"""Tests for v2.6.0 rules (CG-017 through CG-021), LibCST F() patcher, and parallel scanner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.scanner.ast_rules import scan_project, scan_source_code

runner = CliRunner()


# ============================================================================
# Rule CG-017: Django F() Expression Optimization
# ============================================================================


def test_cg017_detects_in_memory_django_arithmetic() -> None:
    """CG-017 detects in-memory arithmetic on Django model before save()."""
    code = """
def deduct(user_id: int, amount: float):
    wallet = Wallet.objects.get(id=user_id)
    wallet.balance -= amount
    wallet.save()
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-017"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-017"
    assert "F()" in findings[0].message
    assert "filter(...).update" in findings[0].suggested_fix_hint


def test_cg017_detects_binop_assign_arithmetic() -> None:
    """CG-017 detects balance = balance - amount on Django model."""
    code = """
def deduct(user_id: int, amount: float):
    wallet = Wallet.objects.get(id=user_id)
    wallet.balance = wallet.balance - amount
    wallet.save()
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-017"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-017"


def test_cg017_ignores_when_f_expression_used() -> None:
    """CG-017 does NOT flag when F() expression is used."""
    code = """
from django.db.models import F

def deduct(user_id: int, amount: float):
    wallet = Wallet.objects.get(id=user_id)
    wallet.balance = F("balance") - amount
    wallet.save()
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-017"]
    assert len(findings) == 0


def test_cg017_auto_patcher_transforms_to_f_expression() -> None:
    """CG-017 auto-patcher converts in-memory arithmetic to F() expression and adds import."""
    code = """def deduct(user_id: int, amount: float):
    wallet = Wallet.objects.get(id=user_id)
    wallet.balance -= amount
    wallet.save()
"""
    patched = apply_all_fixes(code, rules={"CG-017"})
    assert 'from django.db.models import F' in patched
    assert 'wallet.balance = F("balance") - amount' in patched

    # Re-scan patched code: no CG-017 findings remain
    new_findings = [f for f in scan_source_code(patched) if f.rule_id == "CG-017"]
    assert len(new_findings) == 0


# ============================================================================
# Rule CG-018: Distributed Lock TTL & Unsafe Release
# ============================================================================


def test_cg018_detects_unsafe_redis_lock_delete() -> None:
    """CG-018 detects redis.delete(lock_key) or client.delete('lock:123')."""
    code = """
def process_order(order_id: str):
    lock_key = f"lock:order:{order_id}"
    redis_client.set(lock_key, "token", nx=True, ex=10)
    # Critical section...
    redis_client.delete(lock_key)
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-018"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-018"
    assert "Unsafe distributed lock release" in findings[0].message
    assert "Lua script" in findings[0].suggested_fix_hint


def test_cg018_detects_string_literal_lock_delete() -> None:
    """CG-018 detects client.delete('locks:payment')."""
    code = """
def release():
    r.delete("locks:payment")
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-018"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-018"


def test_cg018_ignores_non_lock_redis_delete() -> None:
    """CG-018 does NOT trigger when deleting regular cache keys."""
    code = """
def clear_user_cache(user_id: int):
    redis_client.delete(f"user:profile:{user_id}")
    redis_client.delete("homepage_banner")
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-018"]
    assert len(findings) == 0


# ============================================================================
# Rule CG-019: FastAPI BackgroundTasks DB Session Leak
# ============================================================================


def test_cg019_detects_db_session_passed_to_background_tasks() -> None:
    """CG-019 flags passing request-scoped db session to background_tasks.add_task."""
    code = """
@app.post("/checkout")
async def checkout(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    background_tasks.add_task(send_receipt, db, order_id=123)
    return {"status": "ok"}
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-019"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-019"
    assert "BackgroundTasks session leak" in findings[0].message
    assert "dedicated database session" in findings[0].suggested_fix_hint


def test_cg019_detects_session_keyword_arg() -> None:
    """CG-019 flags passing db session via keyword argument to add_task."""
    code = """
async def handler(tasks: BackgroundTasks, session: AsyncSession):
    tasks.add_task(audit_log, event="purchase", db=session)
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-019"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-019"


def test_cg019_ignores_primitive_arguments() -> None:
    """CG-019 does NOT flag when passing primitive IDs to background tasks."""
    code = """
@app.post("/checkout")
async def checkout(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    background_tasks.add_task(send_receipt, order_id=123, user_email="test@example.com")
    return {"status": "ok"}
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-019"]
    assert len(findings) == 0


# ============================================================================
# Rule CG-020: Unbounded Lock Held Across Network I/O
# ============================================================================


def test_cg020_detects_http_call_inside_transaction_atomic() -> None:
    """CG-020 flags HTTP requests made inside transaction.atomic() with held row lock."""
    code = """
def charge_customer(user_id: int, amount: float):
    with transaction.atomic():
        wallet = Wallet.objects.select_for_update().get(id=user_id)
        resp = httpx.post("https://api.stripe.com/v1/charges", json={"amount": amount})
        wallet.balance -= amount
        wallet.save()
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-020"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-020"
    assert "Unbounded lock held across network I/O" in findings[0].message
    assert "connection pool" in findings[0].suggested_fix_hint or "before acquiring" in findings[0].suggested_fix_hint


def test_cg020_detects_requests_inside_sync_lock() -> None:
    """CG-020 flags requests.get inside with lock:."""
    code = """
def sync_data():
    with my_lock:
        data = requests.get("https://upstream-api.com/feed").json()
        cache.update(data)
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-020"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-020"


def test_cg020_ignores_network_call_outside_lock() -> None:
    """CG-020 does NOT flag when network call happens before acquiring lock."""
    code = """
def charge_customer(user_id: int, amount: float):
    resp = httpx.post("https://api.stripe.com/v1/charges", json={"amount": amount})
    with transaction.atomic():
        wallet = Wallet.objects.select_for_update().get(id=user_id)
        wallet.balance -= amount
        wallet.save()
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-020"]
    assert len(findings) == 0


# ============================================================================
# Rule CG-021: Generator / Coroutine Lock Leak
# ============================================================================


def test_cg021_detects_yield_inside_with_lock() -> None:
    """CG-021 flags yield inside a with lock: context."""
    code = """
def stream_items():
    with item_lock:
        for item in source:
            yield item
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-021"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-021"
    assert "Generator lock leak" in findings[0].message
    assert "yield" in findings[0].suggested_fix_hint or "per item" in findings[0].suggested_fix_hint


def test_cg021_detects_yield_inside_async_lock() -> None:
    """CG-021 flags yield inside async with async_lock:."""
    code = """
async def stream_batches():
    async with cache_lock:
        yield [1, 2, 3]
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-021"]
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-021"


def test_cg021_ignores_yield_outside_lock() -> None:
    """CG-021 does NOT flag when yield is outside the lock."""
    code = """
def stream_items():
    with item_lock:
        items = list(source)
    for item in items:
        yield item
"""
    findings = [f for f in scan_source_code(code) if f.rule_id == "CG-021"]
    assert len(findings) == 0


# ============================================================================
# Parallel Scanning & CLI --workers
# ============================================================================


def test_parallel_scan_produces_identical_results(tmp_path: Path) -> None:
    """scan_project with workers=4 produces identical results to single worker."""
    files: list[Path] = []
    for i in range(6):
        f = tmp_path / f"file_{i}.py"
        if i % 2 == 0:
            f.write_text("""
def bad_generator():
    with my_lock:
        yield 42
""", encoding="utf-8")
        else:
            f.write_text("""
def good_generator():
    yield 42
""", encoding="utf-8")
        files.append(f)

    single_worker_findings = scan_project(files, roots=[tmp_path], workers=1)
    multi_worker_findings = scan_project(files, roots=[tmp_path], workers=4)

    assert len(single_worker_findings) == 3
    assert len(multi_worker_findings) == 3
    single_rules = sorted(f.rule_id for f in single_worker_findings)
    multi_rules = sorted(f.rule_id for f in multi_worker_findings)
    assert single_rules == multi_rules == ["CG-021", "CG-021", "CG-021"]


def test_cli_scan_with_workers_flag(tmp_path: Path) -> None:
    """CLI scan accepts --workers flag and executes cleanly."""
    target = tmp_path / "app.py"
    target.write_text("""
def release():
    redis.delete("lock:session")
""", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--workers", "4", "--format", "json", "--no-cache"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert any(f["rule_id"] == "CG-018" for f in data["findings"])

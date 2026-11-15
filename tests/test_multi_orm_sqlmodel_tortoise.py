"""Comprehensive test suite for SQLModel and Tortoise ORM race condition detection,

sanitizers, and LibCST auto-remediation.
"""

from __future__ import annotations

import ast

from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.scanner.ast_rules import scan_source_code

# ---------------------------------------------------------------------------
# SQLModel Tests
# ---------------------------------------------------------------------------


def test_sqlmodel_cg001_unlocked_read_modify_write() -> None:
    """Detects race condition on await session.exec(select(Wallet)...) with mutation and commit."""
    code = """
async def update_wallet(session, user_id: int, amount: float):
    wallet = (await session.exec(select(Wallet).where(Wallet.user_id == user_id))).first()
    wallet.balance += amount
    await session.commit()
"""
    findings = scan_source_code(code)
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 1
    assert cg001_findings[0].function_name == "update_wallet"
    assert "with_for_update" in cg001_findings[0].suggested_fix_hint


def test_sqlmodel_cg001_with_for_update_sanitized() -> None:
    """Asserts 0 findings when .with_for_update() is present on SQLModel select()."""
    code = """
async def update_wallet_safe(session, user_id: int, amount: float):
    stmt = select(Wallet).where(Wallet.user_id == user_id).with_for_update()
    wallet = (await session.exec(stmt)).first()
    wallet.balance += amount
    await session.commit()
"""
    findings = scan_source_code(code)
    assert not any(f.rule_id == "CG-001" for f in findings)


def test_sqlmodel_cg003_session_exec_in_loop() -> None:
    """Detects loop N+1 query vulnerability when session.exec(...) is inside a loop."""
    code = """
async def process_batch(session, user_ids: list[int]):
    results = []
    for uid in user_ids:
        wallet = (await session.exec(select(Wallet).where(Wallet.user_id == uid))).first()
        results.append(wallet)
    return results
"""
    findings = scan_source_code(code)
    cg003_findings = [f for f in findings if f.rule_id == "CG-003"]
    assert len(cg003_findings) == 1
    assert cg003_findings[0].function_name == "process_batch"


def test_sqlmodel_libcst_autofix() -> None:
    """Verifies LibCST auto-fix injects .with_for_update() into session.exec(select(Wallet)...)."""
    code = """
async def update_wallet(session, user_id: int, amount: float):
    wallet = (await session.exec(select(Wallet).where(Wallet.user_id == user_id))).first()
    wallet.balance += amount
    await session.commit()
"""
    patched = apply_all_fixes(code, rules={"CG-001"})
    assert ".with_for_update()" in patched
    assert "select(Wallet).where(Wallet.user_id == user_id).with_for_update()" in patched
    # Ensure syntax is valid
    ast.parse(patched)
    # Ensure 0 findings on patched code
    assert not any(f.rule_id == "CG-001" for f in scan_source_code(patched))


# ---------------------------------------------------------------------------
# Tortoise ORM Tests
# ---------------------------------------------------------------------------


def test_tortoise_cg001_filter_first_unlocked() -> None:
    """Detects race condition on await Wallet.filter(...).first() with mutation and save."""
    code = """
async def debit_wallet(user_id: int, amount: float):
    wallet = await Wallet.filter(user_id=user_id).first()
    wallet.balance -= amount
    await wallet.save()
"""
    findings = scan_source_code(code)
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 1
    assert cg001_findings[0].function_name == "debit_wallet"


def test_tortoise_cg001_get_unlocked() -> None:
    """Detects race condition on await Wallet.get(...) with mutation and save."""
    code = """
async def debit_wallet(user_id: int, amount: float):
    wallet = await Wallet.get(user_id=user_id)
    wallet.balance = wallet.balance - amount
    await wallet.save()
"""
    findings = scan_source_code(code)
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 1
    assert cg001_findings[0].function_name == "debit_wallet"


def test_tortoise_cg001_select_for_update_sanitized() -> None:
    """Asserts 0 findings when .select_for_update() is present in Tortoise query."""
    code = """
async def debit_wallet_safe(user_id: int, amount: float):
    wallet = await Wallet.filter(user_id=user_id).select_for_update().first()
    wallet.balance -= amount
    await wallet.save()
"""
    findings = scan_source_code(code)
    assert not any(f.rule_id == "CG-001" for f in findings)


def test_tortoise_cg001_in_transaction_atomic() -> None:
    """Asserts atomic operations with F() expressions do not trigger CG-001 false positives."""
    code = """
async def credit_atomic(user_id: int, amount: float):
    await Wallet.filter(user_id=user_id).update(balance=F("balance") + amount)
"""
    findings = scan_source_code(code)
    assert not any(f.rule_id == "CG-001" for f in findings)


def test_tortoise_cg003_query_in_loop() -> None:
    """Detects loop N+1 query vulnerability when Tortoise Model.filter is in a loop."""
    code = """
async def get_wallets(user_ids: list[int]):
    wallets = []
    for uid in user_ids:
        w = await Wallet.filter(user_id=uid).first()
        wallets.append(w)
    return wallets
"""
    findings = scan_source_code(code)
    cg003_findings = [f for f in findings if f.rule_id == "CG-003"]
    assert len(cg003_findings) == 1
    assert cg003_findings[0].function_name == "get_wallets"


def test_tortoise_libcst_autofix_filter_first() -> None:
    """Verifies auto-fix transforms await Wallet.filter(...).first() into select_for_update().first()."""
    code = """
async def debit_wallet(user_id: int, amount: float):
    wallet = await Wallet.filter(user_id=user_id).first()
    wallet.balance -= amount
    await wallet.save()
"""
    patched = apply_all_fixes(code, rules={"CG-001"})
    assert "Wallet.filter(user_id=user_id).select_for_update().first()" in patched
    ast.parse(patched)
    assert not any(f.rule_id == "CG-001" for f in scan_source_code(patched))


def test_tortoise_libcst_autofix_get() -> None:
    """Verifies auto-fix transforms await Wallet.get(...) into Wallet.select_for_update().get(...)."""
    code = """
async def debit_wallet(user_id: int, amount: float):
    wallet = await Wallet.get(user_id=user_id)
    wallet.balance -= amount
    await wallet.save()
"""
    patched = apply_all_fixes(code, rules={"CG-001"})
    assert "Wallet.select_for_update().get(user_id=user_id)" in patched
    ast.parse(patched)
    assert not any(f.rule_id == "CG-001" for f in scan_source_code(patched))


# ---------------------------------------------------------------------------
# Idempotency & AST Round-Trip Tests
# ---------------------------------------------------------------------------


def test_sqlmodel_autofix_idempotent() -> None:
    """Verifies running auto-fix twice on SQLModel code produces identical results."""
    code = """
async def update_wallet(session, user_id: int, amount: float):
    wallet = (await session.exec(select(Wallet).where(Wallet.user_id == user_id))).first()
    wallet.balance += amount
    await session.commit()
"""
    first_pass = apply_all_fixes(code, rules={"CG-001"})
    second_pass = apply_all_fixes(first_pass, rules={"CG-001"})
    assert first_pass == second_pass
    assert first_pass.count(".with_for_update()") == 1


def test_tortoise_autofix_idempotent() -> None:
    """Verifies running auto-fix twice on Tortoise code produces identical results."""
    code = """
async def debit_wallet(user_id: int, amount: float):
    wallet = await Wallet.filter(user_id=user_id).first()
    wallet.balance -= amount
    await wallet.save()
"""
    first_pass = apply_all_fixes(code, rules={"CG-001"})
    second_pass = apply_all_fixes(first_pass, rules={"CG-001"})
    assert first_pass == second_pass
    assert first_pass.count(".select_for_update()") == 1


def test_tortoise_chained_filter_order_by_autofix() -> None:
    """Verifies chained query methods like .filter().order_by().first() are properly patched."""
    code = """
async def get_latest_txn(user_id: int):
    txn = await Transaction.filter(user_id=user_id).order_by("-timestamp").first()
    txn.status = "processed"
    await txn.save()
"""
    findings = scan_source_code(code)
    assert any(f.rule_id == "CG-001" for f in findings)

    patched = apply_all_fixes(code, rules={"CG-001"})
    assert "Transaction.filter(user_id=user_id).order_by(\"-timestamp\").select_for_update().first()" in patched
    ast.parse(patched)
    assert not any(f.rule_id == "CG-001" for f in scan_source_code(patched))

"""Unit tests for Phase 1 AST concurrency scanner rules."""

from __future__ import annotations

from concurrency_guard.scanner.ast_rules import scan_source_code


def test_detects_unlocked_augassign_rmw() -> None:
    """Verifies CG-001 triggers on wallet.balance -= amount without .with_for_update()."""
    code = """
async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    findings = scan_source_code(code)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CG-001"
    assert finding.function_name == "withdraw"
    assert finding.lineno == 3
    assert "with_for_update" in finding.suggested_fix_hint


def test_detects_unlocked_binop_assign_rmw() -> None:
    """Verifies CG-001 triggers on wallet.balance = wallet.balance - amount without .with_for_update()."""
    code = """
async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance = wallet.balance - amount
    await db.commit()
"""
    findings = scan_source_code(code)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CG-001"
    assert finding.function_name == "withdraw"
    assert finding.lineno == 3


def test_ignores_locked_select_for_update() -> None:
    """Verifies 0 findings when .with_for_update() is present."""
    code = """
async def withdraw_safe(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id).with_for_update()
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_ignores_read_only_endpoint() -> None:
    """Verifies 0 findings when select() is called without state mutation or commit()."""
    code = """
async def get_balance(db, user_id):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    return wallet.balance
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


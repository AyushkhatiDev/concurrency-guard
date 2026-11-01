"""Unit tests for Phase 4 LibCST auto-patcher."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from concurrency_guard.patcher.cst_fixer import apply_with_for_update_fix
from concurrency_guard.runner.barrier_engine import run_barrier_test
from concurrency_guard.scanner.ast_rules import scan_source_code


def test_unlocked_select_patched_with_for_update() -> None:
    """Verifies unlocked select statements are patched with .with_for_update()."""
    code = """
async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    patched = apply_with_for_update_fix(code)
    assert ".with_for_update()" in patched
    assert "select(Wallet).where(Wallet.user_id == user_id).with_for_update()" in patched


def test_scan_returns_zero_findings_on_patched_code() -> None:
    """Verifies that running AST scan on patched code returns 0 CG-001 findings."""
    code = """
async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    # Before patch: CG-001 triggers
    findings_before = scan_source_code(code)
    assert any(f.rule_id == "CG-001" for f in findings_before)

    # After patch: 0 findings
    patched = apply_with_for_update_fix(code)
    findings_after = scan_source_code(patched)
    assert len(findings_after) == 0


@pytest.mark.asyncio
async def test_verify_passes_on_patched_code() -> None:
    """Verifies that running barrier test on patched code passes with 0 invariant violations."""
    vulnerable_source = Path("examples/vulnerable_wallet.py").read_text(encoding="utf-8")
    patched_source = apply_with_for_update_fix(vulnerable_source)

    # The patched source must have with_for_update in withdraw
    assert "with_for_update" in patched_source

    mod_name = "test_dynamically_patched_wallet"
    mod = types.ModuleType(mod_name)
    mod.__file__ = "dynamically_patched_wallet.py"
    sys.modules[mod_name] = mod
    exec(patched_source, mod.__dict__)  # noqa: S102

    result = await run_barrier_test(
        app=mod.app,
        endpoint="/wallet/withdraw",
        workers=20,
        initial_balance=50,
        withdraw_amount=50,
        engine=mod.engine,
        session_factory=mod.async_session,
        wallet_model=mod.Wallet,
        base_metadata=mod.Base.metadata,
        headers={"Idempotency-Key": "test-patched-key"},
    )

    assert result["workers"] == 20
    assert result["success_count"] == 1
    assert result["final_balance"] == 0
    assert result["invariant_violated"] is False

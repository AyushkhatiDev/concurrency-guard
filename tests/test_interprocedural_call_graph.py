"""Unit and integration tests for module-level inter-procedural call-graph taint and sanitizer analysis."""

from __future__ import annotations

import time

from concurrency_guard.call_graph import build_module_function_summaries
from concurrency_guard.patcher.cst_fixer import apply_with_for_update_fix
from concurrency_guard.scanner.ast_rules import scan_source_code


def test_helper_query_source_flags_cg001() -> None:
    """Helper returns unlocked ORM entity; caller mutates and commits -> CG-001 flagged."""
    code = """
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import User

async def get_account(db: AsyncSession, user_id: int):
    return await db.scalar(select(User).where(User.id == user_id))

async def update_balance(db: AsyncSession, user_id: int):
    user = await get_account(db, user_id)
    user.balance -= 50
    await db.commit()
"""
    findings = scan_source_code(code, "example_helper_source.py")
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 1
    assert cg001_findings[0].function_name == "update_balance"
    assert "Unlocked Read-Modify-Write" in cg001_findings[0].message


def test_helper_locked_sanitizer_zero_findings() -> None:
    """Helper returns entity with .with_for_update(); caller mutates and commits -> 0 findings."""
    code = """
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import User

async def get_account_locked(db: AsyncSession, user_id: int):
    return await db.scalar(select(User).where(User.id == user_id).with_for_update())

async def safe_update_balance(db: AsyncSession, user_id: int):
    user = await get_account_locked(db, user_id)
    user.balance -= 50
    await db.commit()
"""
    findings = scan_source_code(code, "example_helper_locked.py")
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 0


def test_helper_parameter_mutation_flags_cg001() -> None:
    """Route queries unlocked entity and passes it to helper that mutates it; commits -> CG-001 flagged."""
    code = """
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import User

def apply_penalty(account, penalty: int):
    account.balance -= penalty

async def deduct_penalty_route(db: AsyncSession, user_id: int):
    user = await db.scalar(select(User).where(User.id == user_id))
    apply_penalty(user, 100)
    await db.commit()
"""
    findings = scan_source_code(code, "example_helper_param_mutation.py")
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 1
    assert cg001_findings[0].function_name == "deduct_penalty_route"


def test_helper_commit_delegation_flags_cg001() -> None:
    """Route reads unlocked entity, mutates it, and delegates commit to helper -> CG-001 flagged."""
    code = """
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import User

async def save_and_commit(session: AsyncSession):
    await session.commit()

async def process_refund_route(db: AsyncSession, user_id: int):
    user = await db.scalar(select(User).where(User.id == user_id))
    user.balance += 50
    await save_and_commit(db)
"""
    findings = scan_source_code(code, "example_commit_delegation.py")
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 1
    assert cg001_findings[0].function_name == "process_refund_route"


def test_recursive_helper_immunity() -> None:
    """Direct and mutually recursive helpers terminate cleanly without RecursionError in <100ms."""
    code = """
def helper_a(x):
    if x <= 0:
        return x
    return helper_b(x - 1)

def helper_b(x):
    if x <= 0:
        return x
    return helper_a(x - 1)

async def route_handler(db, val):
    result = helper_a(val)
    return result
"""
    start_time = time.perf_counter()
    summaries = build_module_function_summaries(code)
    findings = scan_source_code(code, "example_recursion.py")
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    assert "helper_a" in summaries
    assert "helper_b" in summaries
    assert len(findings) == 0
    assert elapsed_ms < 100.0, f"Analysis took {elapsed_ms:.2f}ms, expected < 100ms"


def test_unrelated_helper_call_zero_false_positives() -> None:
    """Route reads entity, calls read-only helper (logging only), and commits -> 0 findings."""
    code = """
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import User

def log_user_info(user):
    print("User info:", user.id, user.balance)

async def read_and_log_route(db: AsyncSession, user_id: int):
    user = await db.scalar(select(User).where(User.id == user_id))
    log_user_info(user)
    await db.commit()
"""
    findings = scan_source_code(code, "example_unrelated_helper.py")
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 0


def test_helper_lock_context_sanitizer() -> None:
    """Helper performs mutation inside lock context -> caller mutation is sanitized with 0 findings."""
    code = """
import asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import User

lock = asyncio.Lock()

async def safe_debit(account, amount: int):
    async with lock:
        account.balance -= amount

async def transfer_route(db: AsyncSession, user_id: int):
    user = await db.scalar(select(User).where(User.id == user_id))
    await safe_debit(user, 25)
    await db.commit()
"""
    findings = scan_source_code(code, "example_helper_lock_sanitizer.py")
    cg001_findings = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001_findings) == 0


def test_helper_check_then_act_cg004_propagation() -> None:
    """Helper performs query existence check; caller adds record and commits -> CG-004 flagged."""
    code = """
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models import User

async def check_user_exists(db: AsyncSession, email: str):
    return await db.scalar(select(User).where(User.email == email))

async def register_route(db: AsyncSession, email: str):
    existing = await check_user_exists(db, email)
    if not existing:
        db.add(User(email=email))
        await db.commit()
"""
    findings = scan_source_code(code, "example_cta_helper.py")
    cg004_findings = [f for f in findings if f.rule_id == "CG-004"]
    assert len(cg004_findings) == 1
    assert cg004_findings[0].function_name == "register_route"


def test_cst_fixer_patches_helper_function() -> None:
    """LibCST WithForUpdateTransformer appends .with_for_update() to select in helper."""
    code = """from sqlalchemy import select
from models import User

def fetch_account(db, user_id: int):
    return db.scalar(select(User).where(User.id == user_id))

async def update_route(db, user_id: int):
    user = await fetch_account(db, user_id)
    user.balance -= 50
    await db.commit()
"""
    fixed = apply_with_for_update_fix(code)
    assert ".with_for_update()" in fixed

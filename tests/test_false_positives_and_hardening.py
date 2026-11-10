"""Adversarial regression test suite for zero-hallucination hardening, sanitizers, pragmas, and LibCST idempotency."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.patcher.cst_fixer import apply_all_fixes, apply_all_fixes_with_report
from concurrency_guard.scanner.ast_rules import scan_source_code
from concurrency_guard.scanner.suppression import SuppressionFilter

runner = CliRunner()


def test_pure_read_only_endpoint_zero_findings() -> None:
    """Read-only async endpoints without commits must produce 0 findings."""
    code = """
from sqlalchemy import select

async def get_user_profile(user_id: int, db: AsyncSession):
    stmt = select(User).where(User.id == user_id)
    user = await db.scalar(stmt)
    if not user:
        return None
    return {"id": user.id, "balance": user.balance}
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_unrelated_local_mutation_zero_findings() -> None:
    """Endpoints fetching an entity but mutating unrelated local variables/metrics must produce 0 findings."""
    code = """
from sqlalchemy import select

async def get_user_with_metrics(user_id: int, db: AsyncSession, metrics):
    stmt = select(User).where(User.id == user_id)
    user = await db.scalar(stmt)
    metrics.access_count += 1
    local_cache = {}
    local_cache["last_seen"] = user.id
    return user
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_read_and_commit_unrelated_model_zero_findings() -> None:
    """Reading an entity, creating and committing an unrelated audit log must NOT flag CG-001 on the read entity."""
    code = """
from sqlalchemy import select

async def view_item_and_audit(item_id: int, user_id: int, db: AsyncSession):
    item = await db.get(Item, item_id)
    audit = AuditLog(item_id=item_id, user_id=user_id)
    db.add(audit)
    await db.commit()
    return item
"""
    findings = scan_source_code(code)
    cg001 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001) == 0


def test_sqlalchemy_atomic_update_where_zero_findings() -> None:
    """Atomic SQL UPDATE...WHERE expressions must produce 0 findings for CG-001."""
    code = """
from sqlalchemy import update

async def deduct_balance_atomic(user_id: int, amount: float, db: AsyncSession):
    stmt = update(Wallet).where(Wallet.user_id == user_id).values(balance=Wallet.balance - amount)
    await db.execute(stmt)
    await db.commit()
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_async_lock_sanitizer_zero_findings() -> None:
    """RMW wrapped in 'async with lock:' context manager must produce 0 findings."""
    code = """
from sqlalchemy import select

async def withdraw_locked(user_id: int, amount: float, db: AsyncSession, lock: asyncio.Lock):
    async with lock:
        stmt = select(Wallet).where(Wallet.user_id == user_id)
        wallet = await db.scalar(stmt)
        wallet.balance -= amount
        await db.commit()
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_redis_distributed_lock_sanitizer_zero_findings() -> None:
    """RMW wrapped in 'async with redis.lock(...):' must produce 0 findings."""
    code = """
from sqlalchemy import select

async def withdraw_redis(user_id: int, amount: float, db: AsyncSession, redis_client):
    async with redis_client.lock(f"wallet:{user_id}"):
        stmt = select(Wallet).where(Wallet.user_id == user_id)
        wallet = await db.scalar(stmt)
        wallet.balance -= amount
        await db.commit()
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_advisory_lock_sanitizer_zero_findings() -> None:
    """RMW wrapped in 'async with advisory_lock(...):' must produce 0 findings."""
    code = """
from sqlalchemy import select

async def withdraw_advisory(user_id: int, amount: float, db: AsyncSession):
    async with advisory_lock(user_id):
        stmt = select(Wallet).where(Wallet.user_id == user_id)
        wallet = await db.scalar(stmt)
        wallet.balance -= amount
        await db.commit()
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_cg004_integrity_error_guard_zero_findings() -> None:
    """Check-then-act wrapping commit in try...except IntegrityError must produce 0 findings."""
    code = """
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

async def register_user_safe(email: str, db: AsyncSession):
    existing = await db.scalar(select(User).where(User.email == email))
    if not existing:
        try:
            db.add(User(email=email))
            await db.commit()
        except IntegrityError:
            await db.rollback()
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_cg004_with_lock_sanitizer_zero_findings() -> None:
    """Check-then-act protected by async lock must produce 0 findings."""
    code = """
from sqlalchemy import select

async def register_user_locked(email: str, db: AsyncSession, lock: asyncio.Lock):
    async with lock:
        existing = await db.scalar(select(User).where(User.email == email))
        if not existing:
            db.add(User(email=email))
            await db.commit()
"""
    findings = scan_source_code(code)
    assert len(findings) == 0


def test_cguard_ignore_inline_pragma() -> None:
    """Verify '# cguard: ignore' suppresses findings on that line."""
    code = """
from sqlalchemy import select

async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)  # cguard: ignore
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    sf = SuppressionFilter()
    sf.parse_source(code, filepath="<memory>")
    raw_findings = scan_source_code(code)
    assert len(raw_findings) == 1
    filtered = sf.filter_findings(raw_findings, file_path=Path("<memory>"))
    assert len(filtered) == 0
    assert sf.suppressed_count == 1


def test_cguard_ignore_rule_specific_pragma() -> None:
    """Verify '# cguard: ignore[CG-001]' suppresses only CG-001."""
    code = """
from sqlalchemy import select

async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)  # cguard: ignore[CG-001]
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    sf = SuppressionFilter()
    sf.parse_source(code, filepath="<memory>")
    raw_findings = scan_source_code(code)
    filtered = sf.filter_findings(raw_findings, file_path=Path("<memory>"))
    assert len(filtered) == 0
    assert sf.suppressed_count == 1


def test_cguard_block_and_file_suppression() -> None:
    """Verify '# cguard: ignore-file' and '# cguard: ignore-start' / 'ignore-end'."""
    file_code = """# cguard: ignore-file[CG-001]
from sqlalchemy import select

async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    sf = SuppressionFilter()
    sf.parse_source(file_code, filepath="<memory>")
    filtered = sf.filter_findings(scan_source_code(file_code), file_path=Path("<memory>"))
    assert len(filtered) == 0

    block_code = """
from sqlalchemy import select

# cguard: ignore-start[CG-001]
async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
# cguard: ignore-end[CG-001]
"""
    sf2 = SuppressionFilter()
    sf2.parse_source(block_code, filepath="<memory>")
    filtered2 = sf2.filter_findings(scan_source_code(block_code), file_path=Path("<memory>"))
    assert len(filtered2) == 0


def test_libcst_patcher_is_idempotent() -> None:
    """Running apply_all_fixes multiple times in a row must be completely idempotent."""
    code = """
from fastapi import FastAPI, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

app = FastAPI()

@app.post("/redeem")
async def redeem_coupon(code: str, db: AsyncSession):
    stmt = select(Coupon).where(Coupon.code == code)
    coupon = await db.scalar(stmt)
    if coupon and coupon.remaining_uses > 0:
        coupon.remaining_uses -= 1
        await db.commit()
"""
    # Pass 1: fixes CG-001 (.with_for_update()) and CG-002 (Idempotency-Key)
    pass1 = apply_all_fixes(code)
    assert ".with_for_update()" in pass1
    assert 'alias="Idempotency-Key"' in pass1

    # Pass 2: must produce identical output (zero redundant modifications)
    pass2 = apply_all_fixes(pass1)
    assert pass2 == pass1

    # Pass 3: verify third execution remains identical
    pass3 = apply_all_fixes(pass2)
    assert pass3 == pass1


def test_libcst_post_patch_verification_gate_aborts_safely() -> None:
    """Post-patch verification gate must abort safely and record skip if syntax or CST verification fails."""
    # Source with already valid code
    code = """
async def clean_function(db, user_id):
    stmt = select(User).where(User.id == user_id).with_for_update()
    user = await db.scalar(stmt)
    return user
"""
    result = apply_all_fixes_with_report(code)
    assert result.code == code
    assert len(result.skipped) == 0


def test_confidence_scoring_on_findings() -> None:
    """Strict rules must assign HIGH confidence; heuristic rules assign MEDIUM confidence."""
    # Strict rule CG-001 -> HIGH
    strict_code = """
from sqlalchemy import select

async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""
    findings = scan_source_code(strict_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-001"
    assert findings[0].confidence == "HIGH"

    # Heuristic rule CG-010 (hardcoded /tmp path) -> MEDIUM
    heuristic_code = """
async def write_temp_log(data: str):
    with open('/tmp/worker_output.log', 'w') as f:
        f.write(data)
"""
    findings_heuristic = scan_source_code(heuristic_code)
    cg010 = [f for f in findings_heuristic if f.rule_id == "CG-010"]
    assert len(cg010) == 1
    assert cg010[0].confidence == "MEDIUM"


def test_cli_confidence_filter(tmp_path: Path) -> None:
    """CLI --confidence high filters out heuristic findings while keeping high confidence ones."""
    file_path = tmp_path / "mixed.py"
    file_path.write_text("""
from sqlalchemy import select

async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()

async def temp_file():
    with open('/tmp/test.log', 'w') as f:
        f.write("hello")
""", encoding="utf-8")

    # Scan with --confidence high
    res_high = runner.invoke(app, ["scan", str(file_path), "--confidence", "high", "--format", "json", "--no-cache"])
    assert res_high.exit_code == 1
    data_high = json.loads(res_high.stdout)
    rule_ids_high = {f["rule_id"] for f in data_high["findings"]}
    assert "CG-001" in rule_ids_high
    assert "CG-010" not in rule_ids_high

    # Scan with all findings
    res_all = runner.invoke(app, ["scan", str(file_path), "--format", "json", "--no-cache"])
    assert res_all.exit_code == 1
    data_all = json.loads(res_all.stdout)
    rule_ids_all = {f["rule_id"] for f in data_all["findings"]}
    assert "CG-001" in rule_ids_all
    assert "CG-010" in rule_ids_all


def test_cli_ignore_pragma_flag(tmp_path: Path) -> None:
    """CLI --ignore-pragma causes inline pragma comments to be ignored."""
    file_path = tmp_path / "suppressed.py"
    file_path.write_text("""
from sqlalchemy import select

async def withdraw(db, user_id, amount):
    stmt = select(Wallet).where(Wallet.user_id == user_id)  # cguard: ignore[CG-001]
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
""", encoding="utf-8")

    # Default: pragma is honored -> 0 findings -> exit code 0
    res_default = runner.invoke(app, ["scan", str(file_path), "--no-cache"])
    assert res_default.exit_code == 0
    assert "All AST concurrency checks passed" in res_default.stdout

    # With --ignore-pragma: pragma is bypassed -> 1 finding -> exit code 1
    res_bypass = runner.invoke(app, ["scan", str(file_path), "--ignore-pragma", "--no-cache"])
    assert res_bypass.exit_code == 1
    assert "Found 1 concurrency vulnerability issue(s)" in res_bypass.stdout

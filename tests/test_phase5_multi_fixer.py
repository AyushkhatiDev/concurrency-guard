"""Unit tests for Phase 5 multi-rule LibCST auto-patcher (CG-001, CG-002, CG-004)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.scanner.ast_rules import scan_source_code

runner = CliRunner()


def test_cg002_idempotency_header_injected() -> None:
    """Verifies CG-002 is fixed by injecting idempotency_key parameter and Header import."""
    code = """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.post("/checkout")
async def checkout(request: CheckoutRequest, db: AsyncSession = Depends(get_db)):
    wallet.balance -= request.amount
    await db.commit()
"""
    # Verify CG-002 is detected before patch
    initial_findings = scan_source_code(code)
    assert any(f.rule_id == "CG-002" for f in initial_findings)

    # Apply patch
    patched = apply_all_fixes(code, rules={"CG-002"})

    # Verify Header is imported and parameter is present
    assert "from fastapi import" in patched and "Header" in patched
    assert 'idempotency_key: str = Header(..., alias="Idempotency-Key")' in patched

    # Verify CG-002 finding is completely resolved
    patched_findings = scan_source_code(patched)
    assert not any(f.rule_id == "CG-002" for f in patched_findings)


def test_cg004_integrity_error_wrapped() -> None:
    """Verifies CG-004 is fixed by wrapping commit in try/except IntegrityError with rollback."""
    code = """
from fastapi import FastAPI, Depends
from sqlalchemy import select

app = FastAPI()

@app.post("/users/register")
async def register(email: str, db: AsyncSession = Depends(get_db), idempotency_key: str = Header(...)):
    stmt = select(User).where(User.email == email)
    existing = await db.scalar(stmt)
    if existing:
        raise HTTPException(status_code=400, detail="User exists")
    user = User(email=email)
    db.add(user)
    await db.commit()
"""
    # Verify CG-004 is detected before patch
    initial_findings = scan_source_code(code)
    assert any(f.rule_id == "CG-004" for f in initial_findings)

    # Apply patch
    patched = apply_all_fixes(code, rules={"CG-004"})

    # Verify try/except IntegrityError wrapping and rollback are present
    assert "try:" in patched
    assert "await db.commit()" in patched
    assert "except IntegrityError:" in patched
    assert "await db.rollback()" in patched
    assert 'raise HTTPException(status_code=409, detail="Concurrent conflict: resource already exists")' in patched
    assert "from sqlalchemy.exc import IntegrityError" in patched

    # Verify CG-004 finding is resolved
    patched_findings = scan_source_code(patched)
    assert not any(f.rule_id == "CG-004" for f in patched_findings)


def test_apply_all_fixes_combined() -> None:
    """Verifies apply_all_fixes resolves CG-001, CG-002, and CG-004 in a single combined pass."""
    combined_code = """
from fastapi import FastAPI, Depends
from sqlalchemy import select

app = FastAPI()

@app.post("/wallet/withdraw")
async def withdraw(user_id: int, amount: float, db: AsyncSession = Depends(get_db)):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()

@app.post("/users/register")
async def register(email: str, db: AsyncSession = Depends(get_db), idempotency_key: str = Header(...)):
    stmt = select(User).where(User.email == email)
    existing = await db.scalar(stmt)
    if existing:
        raise HTTPException(status_code=400, detail="User exists")
    user = User(email=email)
    db.add(user)
    await db.commit()
"""
    initial_findings = scan_source_code(combined_code)
    initial_rules = {f.rule_id for f in initial_findings}
    assert "CG-001" in initial_rules
    assert "CG-002" in initial_rules
    assert "CG-004" in initial_rules

    patched = apply_all_fixes(combined_code)

    # Verify all 3 rules are resolved
    remaining_findings = scan_source_code(patched)
    assert not any(f.rule_id in ("CG-001", "CG-002", "CG-004") for f in remaining_findings)


def test_cli_fix_rule_filter(tmp_path: Path) -> None:
    """Verifies cguard fix --rule CG-001 only patches CG-001 and leaves CG-002 untouched."""
    test_file = tmp_path / "target.py"
    test_file.write_text(
        """
from fastapi import FastAPI, Depends
from sqlalchemy import select

app = FastAPI()

@app.post("/wallet/withdraw")
async def withdraw(user_id: int, amount: float, db: AsyncSession = Depends(get_db)):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
""",
        encoding="utf-8",
    )

    # Run CLI fix filtering for only CG-001 with --write
    result = runner.invoke(app, ["fix", str(test_file), "--rule", "CG-001", "--write"])
    assert result.exit_code == 0

    updated_code = test_file.read_text(encoding="utf-8")
    assert ".with_for_update()" in updated_code
    assert 'alias="Idempotency-Key"' not in updated_code

    remaining = scan_source_code(updated_code)
    remaining_rules = {f.rule_id for f in remaining}
    assert "CG-001" not in remaining_rules
    assert "CG-002" in remaining_rules

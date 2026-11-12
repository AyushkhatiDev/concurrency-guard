"""Adversarial edge-case tests verifying compiler and static analysis hardening."""

import ast
from pathlib import Path

from concurrency_guard.patcher.cst_fixer import apply_all_fixes, apply_all_fixes_with_report
from concurrency_guard.scanner.ast_rules import (
    discover_python_files,
    scan_file,
    scan_source_code,
)


def test_idempotency_transformer_kwargs_and_param_ordering() -> None:
    """Verify IdempotencyHeaderTransformer correctly positions parameters before **kwargs."""
    # Case 1: *args and **kwargs
    code_star_args = """
@app.post("/items")
async def create_item(request: Request, *args, **kwargs):
    await db.commit()
"""
    patched1 = apply_all_fixes(code_star_args, rules={"CG-002"})
    tree1 = ast.parse(patched1)
    fn1 = next(n for n in tree1.body if isinstance(n, ast.AsyncFunctionDef))
    # Ensure idempotency_key is in kwonlyargs because *args is present
    kwonly_names = [arg.arg for arg in fn1.args.kwonlyargs]
    assert "idempotency_key" in kwonly_names
    assert fn1.args.kwarg is not None and fn1.args.kwarg.arg == "kwargs"

    # Case 2: Bare * and keyword-only arguments
    code_bare_star = """
@app.post("/users")
async def create_user(*, user_id: int, **kwargs):
    await db.commit()
"""
    patched2 = apply_all_fixes(code_bare_star, rules={"CG-002"})
    tree2 = ast.parse(patched2)
    fn2 = next(n for n in tree2.body if isinstance(n, ast.AsyncFunctionDef))
    kwonly_names = [arg.arg for arg in fn2.args.kwonlyargs]
    assert "idempotency_key" in kwonly_names
    assert fn2.args.kwarg is not None and fn2.args.kwarg.arg == "kwargs"

    # Case 3: Only **kwargs
    code_only_kwargs = """
@app.post("/generic")
async def generic_post(**kwargs):
    await db.commit()
"""
    patched3 = apply_all_fixes(code_only_kwargs, rules={"CG-002"})
    tree3 = ast.parse(patched3)
    fn3 = next(n for n in tree3.body if isinstance(n, ast.AsyncFunctionDef))
    pos_names = [arg.arg for arg in fn3.args.args]
    assert "idempotency_key" in pos_names
    assert fn3.args.kwarg is not None and fn3.args.kwarg.arg == "kwargs"

    # Case 4: Multi-line signature preservation
    code_multiline = """
@app.post("/multiline")
async def multiline_route(
    request: Request,
    *,
    user_id: int,
    **kwargs,
):
    await db.commit()
"""
    patched4 = apply_all_fixes(code_multiline, rules={"CG-002"})
    tree4 = ast.parse(patched4)
    fn4 = next(n for n in tree4.body if isinstance(n, ast.AsyncFunctionDef))
    assert fn4 is not None
    assert "idempotency_key: str = Header(" in patched4
    assert "**kwargs" in patched4


def test_multi_finding_line_drift_auto_patcher() -> None:
    """Verify that multiple fixes in one file don't drift line numbers or miss targets."""
    code = """
@app.post("/transfer")
async def transfer_money(source_id: int, dest_id: int, amount: float):
    source = (await db.execute(select(Account).where(Account.id == source_id))).scalar_one()
    source.balance -= amount
    await db.commit()
"""
    # Should trigger both CG-002 (missing Header) and CG-001 (unlocked RMW)
    result = apply_all_fixes_with_report(code, rules={"CG-001", "CG-002"})
    patched = result.code
    ast.parse(patched)  # Must be valid Python syntax
    assert "with_for_update" in patched
    assert "idempotency_key" in patched
    assert "from fastapi import Header" in patched

    # Re-scanning the patched code must produce 0 findings for CG-001 and CG-002
    findings_after = scan_source_code(patched)
    active_after = [f for f in findings_after if f.rule_id in {"CG-001", "CG-002"}]
    assert not active_after


def test_nested_scope_isolation_inner_functions_and_classes() -> None:
    """Ensure inner functions, inner classes, and lambdas do not pollute outer scope analysis."""
    # Sub-case A: Outer function is read-only, but inner function mutates local object.
    # Should produce 0 CG-001 findings for outer function.
    code_inner_mutate = """
async def get_user_profile(user_id: int):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one()
    
    def log_helper():
        class Context:
            pass
        ctx = Context()
        ctx.audit = True
        return ctx

    log_helper()
    await db.commit()
    return user
"""
    findings_a = scan_source_code(code_inner_mutate)
    cg001_a = [f for f in findings_a if f.rule_id == "CG-001"]
    assert not cg001_a

    # Sub-case B: Inner function has a lock, but outer function mutates without a lock.
    # The outer function's RMW must NOT be sanitized by the inner function's lock!
    code_inner_lock = """
async def unsafe_outer(user_id: int):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one()

    async def inner_helper():
        async with asyncio.Lock():
            pass

    user.balance -= 50
    await db.commit()
"""
    findings_b = scan_source_code(code_inner_lock)
    cg001_b = [f for f in findings_b if f.rule_id == "CG-001"]
    assert len(cg001_b) == 1

    # Sub-case C: Inner helper has loop query (CG-003), but outer does not.
    code_inner_loop = """
async def outer_service():
    def compute_local():
        for i in range(10):
            pass
        return 42

    compute_local()
"""
    findings_c = scan_source_code(code_inner_loop)
    cg003_c = [f for f in findings_c if f.rule_id == "CG-003"]
    assert not cg003_c


def test_walrus_and_starred_unpacking_rmw() -> None:
    """Verify that walrus (:=) expressions and starred unpacking are tracked for CG-001."""
    # Walrus operator in if-condition
    code_walrus = """
async def process_coupon(code: str):
    if (coupon := await db.scalar(select(Coupon).where(Coupon.code == code))):
        coupon.used = True
        await db.commit()
"""
    findings_walrus = scan_source_code(code_walrus)
    cg001_w = [f for f in findings_walrus if f.rule_id == "CG-001"]
    assert len(cg001_w) == 1

    # Starred unpacking
    code_starred = """
async def process_batch():
    primary, *others = (await db.execute(select(Item))).scalars().all()
    primary.processed = True
    await db.commit()
"""
    findings_starred = scan_source_code(code_starred)
    cg001_s = [f for f in findings_starred if f.rule_id == "CG-001"]
    assert len(cg001_s) == 1


def test_exact_span_bounded_lock_sanitizer() -> None:
    """Verify that lock sanitization strictly requires critical operations within lock spans."""
    # Case 1: Select is under lock, but mutation & commit occur after lock is released -> UNSAFE (CG-001)
    code_select_only_locked = """
async def partial_lock_rmw(user_id: int):
    async with lock:
        user = await db.get(User, user_id)
    
    # Lock released here!
    user.balance -= 100
    await db.commit()
"""
    findings_1 = scan_source_code(code_select_only_locked)
    cg001_1 = [f for f in findings_1 if f.rule_id == "CG-001"]
    assert len(cg001_1) == 1

    # Case 2: Select, mutate, and commit all inside lock -> SAFE (0 findings)
    code_fully_locked = """
async def full_lock_rmw(user_id: int):
    async with lock:
        user = await db.get(User, user_id)
        user.balance -= 100
        await db.commit()
"""
    findings_2 = scan_source_code(code_fully_locked)
    cg001_2 = [f for f in findings_2 if f.rule_id == "CG-001"]
    assert not cg001_2

    # Case 3: CG-004 where unrelated lock exists earlier in function -> UNSAFE (CG-004)
    code_unrelated_lock = """
async def check_then_act(email: str):
    async with lock:
        pass  # Unrelated lock earlier
    
    existing = await db.scalar(select(User).where(User.email == email))
    if not existing:
        db.add(User(email=email))
        await db.commit()
"""
    findings_3 = scan_source_code(code_unrelated_lock)
    cg004_3 = [f for f in findings_3 if f.rule_id == "CG-004"]
    assert len(cg004_3) == 1


def test_multiline_and_span_suppression_pragmas(tmp_path: Path) -> None:
    """Verify # cguard: ignore on multi-line statements and block ranges."""
    code_multiline_ignore = """
async def transfer():
    user = await db.scalar(
        select(User)
        .where(User.id == 1)  # cguard: ignore[CG-001]
    )
    user.balance -= 50
    await db.commit()
"""
    test_file = tmp_path / "test_ignore.py"
    test_file.write_text(code_multiline_ignore, encoding="utf-8")
    findings = scan_file(test_file)
    assert not any(f.rule_id == "CG-001" for f in findings)

    # Block suppression
    code_block = """
# cguard: ignore-start[CG-004]
async def create_unique(email: str):
    existing = await db.scalar(select(User).where(User.email == email))
    if not existing:
        db.add(User(email=email))
        await db.commit()
# cguard: ignore-end[CG-004]
"""
    test_file_block = tmp_path / "test_block.py"
    test_file_block.write_text(code_block, encoding="utf-8")
    findings_block = scan_file(test_file_block)
    assert not any(f.rule_id == "CG-004" for f in findings_block)


def test_utf8_bom_and_excluded_directories(tmp_path: Path) -> None:
    """Verify UTF-8 BOM support and directory filtering."""
    # File with UTF-8 BOM
    bom_file = tmp_path / "bom_test.py"
    bom_content = "\ufeffasync def bad_post():\n    await db.commit()\n"
    bom_file.write_text(bom_content, encoding="utf-8-sig")

    findings = scan_file(bom_file)
    assert isinstance(findings, list)

    # Directory exclusion checks
    excluded_names = [".git", ".tox", ".mypy_cache", ".pytest_cache", ".eggs", "env", ".env"]
    for name in excluded_names:
        d = tmp_path / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "hidden.py").write_text("x = 1\n", encoding="utf-8")

    discovered = discover_python_files(tmp_path)
    discovered_str = [str(p) for p in discovered]
    for name in excluded_names:
        assert not any(f"/{name}/" in p or p.endswith(f"/{name}") for p in discovered_str)


def test_with_for_update_inner_select_attachment() -> None:
    """Verify that WithForUpdateTransformer binds to inner select chain, not outer call."""
    code = """
async def redeem():
    result = await session.execute(
        select(Coupon).where(Coupon.code == code)
    )
    coupon = result.scalar_one()
    coupon.used = True
    await session.commit()
"""
    patched = apply_all_fixes(code, rules={"CG-001"})
    assert "select(Coupon).where(Coupon.code == code).with_for_update()" in patched
    assert "session.execute(" in patched
    assert "session.execute.with_for_update" not in patched

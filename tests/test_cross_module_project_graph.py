"""Tests for Cross-File Project Import Graph & Multi-Module Service-Layer Taint Propagation.

Covers:
1. Repository -> Router Unlocked Taint Propagation (CG-001)
2. Relative Import Resolution (from ..repositories.wallet import get_wallet)
3. Cross-File Sanitizer (.with_for_update()) & Automatic Cache Invalidation
4. Service-Layer Parameter Mutation (services.billing.apply_charge)
5. Circular Import Cycle Immunity (<200ms, zero RecursionError)
6. Module alias calls (await wallet_repo.get_unlocked_wallet)
7. Isolated single-file mode (--no-cross-file / cross_file=False)
"""

from __future__ import annotations

import textwrap
import time
from pathlib import Path

from concurrency_guard.cache.file_cache import FileCache
from concurrency_guard.project_graph import ProjectSymbolGraph, resolve_module_path
from concurrency_guard.scanner.ast_rules import scan_directory, scan_project


def test_repository_to_router_unlocked_taint_propagation(tmp_path: Path) -> None:
    """Test 1: Unlocked query in repository propagates taint to router caller and flags CG-001."""
    app_dir = tmp_path / "app"
    repo_dir = app_dir / "repositories"
    router_dir = app_dir / "routers"
    repo_dir.mkdir(parents=True)
    router_dir.mkdir(parents=True)

    (app_dir / "__init__.py").write_text("", encoding="utf-8")
    (repo_dir / "__init__.py").write_text("", encoding="utf-8")
    (router_dir / "__init__.py").write_text("", encoding="utf-8")

    wallet_repo = repo_dir / "wallet.py"
    wallet_repo.write_text(
        textwrap.dedent("""\
        from sqlalchemy import select
        from app.models import Wallet

        async def get_unlocked_wallet(db, user_id):
            stmt = select(Wallet).where(Wallet.user_id == user_id)
            result = await db.execute(stmt)
            return result.scalar_one_or_none()
        """),
        encoding="utf-8",
    )

    checkout_router = router_dir / "checkout.py"
    checkout_router.write_text(
        textwrap.dedent("""\
        from fastapi import APIRouter
        from app.repositories.wallet import get_unlocked_wallet

        router = APIRouter()

        @router.post("/checkout")
        async def checkout(db, user_id, amount):
            wallet = await get_unlocked_wallet(db, user_id)
            wallet.balance -= amount
            await db.commit()
            return wallet
        """),
        encoding="utf-8",
    )

    findings = scan_directory(app_dir)

    cg001 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001) >= 1
    finding = cg001[0]
    assert "checkout.py" in str(finding.filename)
    assert finding.function_name == "checkout"
    # Verify cross-file origin context in message
    assert "get_unlocked_wallet" in finding.message or "wallet.py" in finding.message


def test_relative_import_resolution(tmp_path: Path) -> None:
    """Test 2: Relative import 'from ..repositories.wallet import get_wallet' resolves accurately."""
    app_dir = tmp_path / "app"
    repo_dir = app_dir / "repositories"
    router_dir = app_dir / "routers"
    repo_dir.mkdir(parents=True)
    router_dir.mkdir(parents=True)

    (app_dir / "__init__.py").write_text("", encoding="utf-8")
    (repo_dir / "__init__.py").write_text("", encoding="utf-8")
    (router_dir / "__init__.py").write_text("", encoding="utf-8")

    wallet_repo = repo_dir / "wallet.py"
    wallet_repo.write_text(
        textwrap.dedent("""\
        from sqlalchemy import select

        async def fetch_wallet(db, user_id):
            stmt = select(Wallet).where(Wallet.user_id == user_id)
            res = await db.execute(stmt)
            return res.scalar_one_or_none()
        """),
        encoding="utf-8",
    )

    checkout_router = router_dir / "checkout.py"
    checkout_router.write_text(
        textwrap.dedent("""\
        from ..repositories.wallet import fetch_wallet

        async def process_payment(db, user_id, total):
            wallet = await fetch_wallet(db, user_id)
            wallet.balance -= total
            await db.commit()
            return {"status": "ok"}
        """),
        encoding="utf-8",
    )

    # Verify direct resolution function
    resolved = resolve_module_path(
        checkout_router,
        "repositories.wallet",
        level=2,
        roots=[app_dir, tmp_path],
    )
    assert resolved is not None
    assert resolved.resolve() == wallet_repo.resolve()

    # Scan and verify CG-001 is flagged via relative import
    findings = scan_directory(app_dir)
    cg001 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001) == 1
    assert "checkout.py" in str(cg001[0].filename)


def test_cross_file_sanitizer_and_cache_invalidation(tmp_path: Path) -> None:
    """Test 3: Adding .with_for_update() in repository invalidates cached router and reports 0 findings."""
    app_dir = tmp_path / "app"
    repo_dir = app_dir / "repositories"
    router_dir = app_dir / "routers"
    cache_dir = tmp_path / ".cguard_cache"
    repo_dir.mkdir(parents=True)
    router_dir.mkdir(parents=True)

    wallet_repo = repo_dir / "wallet.py"
    wallet_repo.write_text(
        textwrap.dedent("""\
        from sqlalchemy import select

        async def get_wallet(db, user_id):
            stmt = select(Wallet).where(Wallet.user_id == user_id)
            result = await db.execute(stmt)
            return result.scalar_one_or_none()
        """),
        encoding="utf-8",
    )

    checkout_router = router_dir / "checkout.py"
    checkout_router.write_text(
        textwrap.dedent("""\
        from app.repositories.wallet import get_wallet

        async def checkout(db, user_id, amount):
            wallet = await get_wallet(db, user_id)
            wallet.balance -= amount
            await db.commit()
            return wallet
        """),
        encoding="utf-8",
    )

    cache_mgr = FileCache(cache_dir=cache_dir, enabled=True)

    # Pass 1: Scan unlocked code -> CG-001 flagged and cached
    findings_1 = scan_project([wallet_repo, checkout_router], roots=[tmp_path], cache_manager=cache_mgr)
    cg001_initial = [f for f in findings_1 if f.rule_id == "CG-001"]
    assert len(cg001_initial) == 1

    # Ensure cache entries exist
    assert len(list(cache_dir.glob("*.json"))) >= 1

    # Pass 2: Sanitize repository with .with_for_update() WITHOUT modifying checkout.py
    time.sleep(0.01)  # Ensure timestamp shift
    wallet_repo.write_text(
        textwrap.dedent("""\
        from sqlalchemy import select

        async def get_wallet(db, user_id):
            stmt = select(Wallet).where(Wallet.user_id == user_id).with_for_update()
            result = await db.execute(stmt)
            return result.scalar_one_or_none()
        """),
        encoding="utf-8",
    )

    # Pass 3: Re-scan with the same cache manager
    # Because wallet.py changed, checkout.py's dependency digest changed -> cache invalidation
    findings_2 = scan_project([wallet_repo, checkout_router], roots=[tmp_path], cache_manager=cache_mgr)
    cg001_sanitized = [f for f in findings_2 if f.rule_id == "CG-001"]
    assert len(cg001_sanitized) == 0


def test_service_layer_parameter_mutation(tmp_path: Path) -> None:
    """Test 4: Route fetches unlocked entity and calls cross-module service to debit -> flags CG-001."""
    services_dir = tmp_path / "services"
    routers_dir = tmp_path / "routers"
    services_dir.mkdir(parents=True)
    routers_dir.mkdir(parents=True)

    billing_service = services_dir / "billing.py"
    billing_service.write_text(
        textwrap.dedent("""\
        async def apply_charge(wallet, amount):
            wallet.balance -= amount
        """),
        encoding="utf-8",
    )

    checkout_router = routers_dir / "checkout.py"
    checkout_router.write_text(
        textwrap.dedent("""\
        from sqlalchemy import select
        from services.billing import apply_charge

        async def checkout(db, user_id, amount):
            stmt = select(Wallet).where(Wallet.user_id == user_id)
            result = await db.execute(stmt)
            wallet = result.scalar_one_or_none()
            await apply_charge(wallet, amount)
            await db.commit()
            return wallet
        """),
        encoding="utf-8",
    )

    findings = scan_project([billing_service, checkout_router], roots=[tmp_path])
    cg001 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001) == 1
    assert "checkout.py" in str(cg001[0].filename)


def test_circular_import_cycle_immunity(tmp_path: Path) -> None:
    """Test 5: Mutual circular imports terminate cleanly in <200ms with zero RecursionError."""
    mod_a = tmp_path / "mod_a.py"
    mod_b = tmp_path / "mod_b.py"

    mod_a.write_text(
        textwrap.dedent("""\
        from mod_b import helper_b

        async def helper_a(db, user_id):
            return await helper_b(db, user_id)
        """),
        encoding="utf-8",
    )

    mod_b.write_text(
        textwrap.dedent("""\
        from mod_a import helper_a

        async def helper_b(db, user_id):
            return await helper_a(db, user_id)
        """),
        encoding="utf-8",
    )

    start = time.perf_counter()
    graph = ProjectSymbolGraph.build([mod_a, mod_b], roots=[tmp_path])
    elapsed_ms = (time.perf_counter() - start) * 1000

    # Must terminate cleanly and swiftly under 200ms
    assert elapsed_ms < 200.0
    assert len(graph.file_summaries) == 2

    # Verify scan also terminates without RecursionError
    findings = scan_project([mod_a, mod_b], roots=[tmp_path])
    assert isinstance(findings, list)


def test_module_qualified_import_call(tmp_path: Path) -> None:
    """Test 6: Module-qualified calls 'await wallet_repo.get_unlocked_wallet' resolve accurately."""
    app_dir = tmp_path / "app"
    repo_dir = app_dir / "repositories"
    router_dir = app_dir / "routers"
    repo_dir.mkdir(parents=True)
    router_dir.mkdir(parents=True)

    wallet_repo = repo_dir / "wallet.py"
    wallet_repo.write_text(
        textwrap.dedent("""\
        from sqlalchemy import select

        async def get_unlocked_wallet(db, user_id):
            stmt = select(Wallet).where(Wallet.user_id == user_id)
            res = await db.execute(stmt)
            return res.scalar_one_or_none()
        """),
        encoding="utf-8",
    )

    checkout_router = router_dir / "checkout.py"
    checkout_router.write_text(
        textwrap.dedent("""\
        import app.repositories.wallet as wallet_repo

        async def checkout(db, user_id, amount):
            wallet = await wallet_repo.get_unlocked_wallet(db, user_id)
            wallet.balance -= amount
            await db.commit()
            return wallet
        """),
        encoding="utf-8",
    )

    findings = scan_project([wallet_repo, checkout_router], roots=[tmp_path])
    cg001 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001) == 1
    assert "checkout.py" in str(cg001[0].filename)


def test_no_cross_file_flag_isolates_scan(tmp_path: Path) -> None:
    """Test 7: Passing cross_file=False suppresses cross-file taint resolution."""
    repo_dir = tmp_path / "repositories"
    router_dir = tmp_path / "routers"
    repo_dir.mkdir(parents=True)
    router_dir.mkdir(parents=True)

    wallet_repo = repo_dir / "wallet.py"
    wallet_repo.write_text(
        textwrap.dedent("""\
        from sqlalchemy import select

        async def get_wallet(db, user_id):
            stmt = select(Wallet).where(Wallet.user_id == user_id)
            res = await db.execute(stmt)
            return res.scalar_one_or_none()
        """),
        encoding="utf-8",
    )

    checkout_router = router_dir / "checkout.py"
    checkout_router.write_text(
        textwrap.dedent("""\
        from repositories.wallet import get_wallet

        async def checkout(db, user_id, amount):
            wallet = await get_wallet(db, user_id)
            wallet.balance -= amount
            await db.commit()
            return wallet
        """),
        encoding="utf-8",
    )

    # When cross_file=False, checkout.py does not know get_wallet returns an unlocked entity
    findings = scan_project([wallet_repo, checkout_router], roots=[tmp_path], cross_file=False)
    cg001 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg001) == 0

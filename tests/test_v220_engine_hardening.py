"""Regression coverage for the v2.2.0 conservative flow and patching rules."""

from __future__ import annotations

import ast

from concurrency_guard.patcher.cst_fixer import apply_all_fixes_with_report
from concurrency_guard.scanner.ast_rules import scan_source_code


def _cg016(source: str):
    return [finding for finding in scan_source_code(source) if finding.rule_id == "CG-016"]


def test_django_alias_chain_inside_atomic_is_detected() -> None:
    source = '''
def withdraw():
    with transaction.atomic():
        wallet = User.objects.get(id=1)
        w = wallet
        w.balance -= 50
        w.save()
'''
    assert len(_cg016(source)) == 1


def test_django_row_lock_inside_atomic_is_not_reported() -> None:
    source = '''
def withdraw():
    with transaction.atomic():
        wallet = User.objects.select_for_update().get(id=1)
        w = wallet
        w.balance -= 50
        w.save()
'''
    assert _cg016(source) == []


def test_async_with_atomic_scope_honors_a_held_row_lock() -> None:
    source = '''
async def withdraw():
    async with transaction.atomic():
        wallet = User.objects.select_for_update().get(id=1)
        wallet.balance -= 50
        wallet.save()
'''
    assert _cg016(source) == []


def test_select_for_update_outside_atomic_is_still_unsafe() -> None:
    source = '''
def withdraw():
    wallet = User.objects.select_for_update().get(id=1)
    wallet.balance -= 50
    wallet.save()
'''
    assert len(_cg016(source)) == 1


def test_branch_local_provenance_is_not_merged_after_the_branch() -> None:
    source = '''
def withdraw(enabled):
    with transaction.atomic():
        if enabled:
            wallet = User.objects.get(id=1)
        wallet.balance -= 50
        wallet.save()
'''
    assert _cg016(source) == []


def test_reassignment_clears_django_provenance() -> None:
    source = '''
def withdraw():
    with transaction.atomic():
        wallet = User.objects.get(id=1)
        wallet = make_ephemeral_wallet()
        wallet.balance -= 50
        wallet.save()
'''
    assert _cg016(source) == []


def test_patcher_skips_kwargs_unpacking_and_reports_manual_review() -> None:
    source = '''
def withdraw(lookup):
    with transaction.atomic():
        wallet = User.objects.get(**lookup)
        wallet.balance -= 50
        wallet.save()
'''
    result = apply_all_fixes_with_report(source, rules={"CG-016"})
    assert result.code == source
    assert result.skipped[0].rule_id == "CG-016"
    assert "**kwargs" in result.skipped[0].reason


def test_patcher_skips_dynamic_dispatch_and_patches_only_static_source() -> None:
    source = '''
def withdraw():
    with transaction.atomic():
        wallet = User.objects.get(id=1)
        helper = getattr(service, "helper")
        wallet.balance -= 50
        wallet.save()
'''
    result = apply_all_fixes_with_report(source, rules={"CG-016"})
    assert result.code == source
    assert result.skipped[0].rule_id == "CG-016"


def test_patched_atomic_django_source_reparses_and_rescans_cleanly() -> None:
    source = '''
def withdraw():
    with transaction.atomic():
        wallet = User.objects.get(id=1)
        wallet.balance -= 50
        wallet.save()
'''
    result = apply_all_fixes_with_report(source, rules={"CG-016"})
    ast.parse(result.code)
    assert "User.objects.select_for_update().get(id=1)" in result.code
    assert _cg016(result.code) == []


def test_taint_does_not_cross_into_nested_function_scope() -> None:
    source = '''
shared = {}

async def outer():
    alias = shared
    def nested():
        alias["count"] = 1
'''
    assert not any(finding.rule_id == "CG-015" for finding in scan_source_code(source))

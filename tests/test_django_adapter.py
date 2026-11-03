"""Django ORM read-modify-write detection and LibCST remediation tests."""

from __future__ import annotations

from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.scanner.ast_rules import scan_source_code


def test_detects_and_patches_django_unlocked_read_modify_write() -> None:
    """Django model mutation is protected by select_for_update after patching."""
    code = '''
from django.db import transaction

def checkout(user_id, amount):
    with transaction.atomic():
        # Preserve the checkout implementation comment.
        user = User.objects.get(id=user_id)
        account = user
        account.balance -= amount
        account.save()
'''
    findings = [finding for finding in scan_source_code(code) if finding.rule_id == "CG-016"]
    assert len(findings) == 1
    assert findings[0].function_name == "checkout"
    assert findings[0].lineno == 7

    patched = apply_all_fixes(code, rules={"CG-016"})

    assert "# Preserve the checkout implementation comment." in patched
    assert "User.objects.select_for_update().get(id=user_id)" in patched
    assert not any(finding.rule_id == "CG-016" for finding in scan_source_code(patched))


def test_django_filter_first_is_detected_and_locked() -> None:
    """The adapter supports the alternate objects.filter(...).first() fetch chain."""
    code = '''
from django.db import transaction

def redeem(code):
    with transaction.atomic():
        coupon = Coupon.objects.filter(code=code).first()
        coupon.remaining_uses -= 1
        coupon.save()
'''
    assert any(finding.rule_id == "CG-016" for finding in scan_source_code(code))

    patched = apply_all_fixes(code, rules={"CG-016"})

    assert "Coupon.objects.select_for_update().filter(code=code).first()" in patched
    assert not any(finding.rule_id == "CG-016" for finding in scan_source_code(patched))

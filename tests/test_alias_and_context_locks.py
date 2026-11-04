"""Tests for Deep Alias Tracking and Context-Aware Lock Detection."""

from __future__ import annotations

from concurrency_guard.scanner.ast_rules import scan_source_code


def _cg016(source: str):
    return [finding for finding in scan_source_code(source) if finding.rule_id == "CG-016"]


def _cg006(source: str):
    return [finding for finding in scan_source_code(source) if finding.rule_id == "CG-006"]


def _cg007(source: str):
    return [finding for finding in scan_source_code(source) if finding.rule_id == "CG-007"]


# ==============================================================================
# Feature 1: Deep Alias Tracking (Semantic Taint Tracking)
# ==============================================================================


def test_alias_reassignment_triggers_cg016_on_mutation() -> None:
    """When a vulnerable fetch is aliased (w = wallet), mutating w triggers CG-016."""
    source = """
def update_balance():
    wallet = User.objects.get(id=1)
    w = wallet
    w.balance -= 50
"""
    findings = _cg016(source)
    assert len(findings) == 1
    assert findings[0].function_name == "update_balance"
    assert findings[0].rule_id == "CG-016"


def test_deep_alias_chain_triggers_cg016() -> None:
    """Multi-hop alias chain w1 -> w2 -> w3 traces back to the vulnerable fetch."""
    source = """
def transfer_funds():
    wallet = User.objects.get(id=1)
    w1 = wallet
    w2 = w1
    w3 = w2
    w3.balance -= 100
"""
    findings = _cg016(source)
    assert len(findings) == 1
    assert findings[0].function_name == "transfer_funds"


def test_multiple_target_assignment_alias_triggers_cg016() -> None:
    """Multiple assignment targets (w1 = w2 = wallet) are all tracked as tainted."""
    source = """
def process():
    wallet = User.objects.get(id=1)
    w1 = w2 = wallet
    w2.balance -= 25
"""
    findings = _cg016(source)
    assert len(findings) == 1
    assert findings[0].function_name == "process"


def test_annotated_assignment_alias_triggers_cg016() -> None:
    """Type-annotated assignment (w: User = wallet) is tracked as tainted."""
    source = """
def process():
    wallet = User.objects.get(id=1)
    w: User = wallet
    w.balance -= 15
"""
    findings = _cg016(source)
    assert len(findings) == 1
    assert findings[0].function_name == "process"


def test_binop_assign_mutation_on_alias_triggers_cg016() -> None:
    """Direct assignment mutation (w.balance = w.balance - 50) triggers CG-016."""
    source = """
def deduct():
    wallet = User.objects.get(id=1)
    w = wallet
    w.balance = w.balance - 50
"""
    findings = _cg016(source)
    assert len(findings) == 1
    assert findings[0].function_name == "deduct"


def test_reassignment_to_clean_value_clears_taint() -> None:
    """Reassigning an alias variable to a non-ORM object clears taint."""
    source = """
def withdraw():
    wallet = User.objects.get(id=1)
    w = wallet
    w = make_safe_dummy()
    w.balance -= 50
"""
    findings = _cg016(source)
    assert findings == []


# ==============================================================================
# Feature 2: Context-Aware Lock Detection
# ==============================================================================


def test_atomic_with_select_for_update_alias_is_safe() -> None:
    """Inside transaction.atomic(), select_for_update() + mutation on alias is safe."""
    source = """
from django.db import transaction

def withdraw():
    with transaction.atomic():
        wallet = User.objects.select_for_update().get(id=1)
        w = wallet
        w.balance -= 50
"""
    findings = _cg016(source)
    assert findings == []


def test_atomic_without_select_for_update_alias_triggers_cg016() -> None:
    """Inside transaction.atomic(), missing select_for_update() triggers CG-016."""
    source = """
from django.db import transaction

def withdraw():
    with transaction.atomic():
        wallet = User.objects.get(id=1)
        w = wallet
        w.balance -= 50
"""
    findings = _cg016(source)
    assert len(findings) == 1
    assert findings[0].function_name == "withdraw"


def test_select_for_update_outside_atomic_triggers_cg016() -> None:
    """Calling select_for_update() outside transaction.atomic() does not hold lock."""
    source = """
def withdraw():
    wallet = User.objects.select_for_update().get(id=1)
    w = wallet
    w.balance -= 50
"""
    findings = _cg016(source)
    assert len(findings) == 1


def test_async_shared_dict_mutation_inside_lock_suppresses_cg006() -> None:
    """Shared dict mutated inside async with lock: block suppresses CG-006."""
    source = """
import asyncio

cache = {}
lock = asyncio.Lock()

async def safe_writer(key, val):
    async with lock:
        cache[key] = val
"""
    findings = _cg006(source)
    assert findings == []


def test_async_shared_dict_mutation_outside_lock_triggers_cg006() -> None:
    """Shared dict mutated outside async with lock: triggers CG-006."""
    source = """
import asyncio

cache = {}

async def unsafe_writer(key, val):
    cache[key] = val
"""
    findings = _cg006(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-006"
    assert findings[0].function_name == "unsafe_writer"


def test_async_shared_dict_mutation_partially_locked_triggers_cg006() -> None:
    """If one mutation is outside async with lock, CG-006 must be reported."""
    source = """
import asyncio

cache = {}
lock = asyncio.Lock()

async def mixed_writer(k1, v1, k2, v2):
    cache[k1] = v1
    async with lock:
        cache[k2] = v2
"""
    findings = _cg006(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-006"


def test_async_shared_dict_alias_inside_lock_suppresses_cg006() -> None:
    """Aliased shared collection (c = cache) mutated inside lock suppresses CG-006."""
    source = """
import asyncio

cache = {}
lock = asyncio.Lock()

async def safe_aliased(key, val):
    c = cache
    async with lock:
        c[key] = val
"""
    findings = _cg006(source)
    assert findings == []


def test_async_shared_dict_alias_outside_lock_triggers_cg006() -> None:
    """Aliased shared collection (c = cache) mutated outside lock triggers CG-006."""
    source = """
import asyncio

cache = {}

async def unsafe_aliased(key, val):
    c = cache
    c[key] = val
"""
    findings = _cg006(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-006"


def test_thread_shared_mutation_inside_with_lock_suppresses_cg007() -> None:
    """Thread target mutating shared list inside with lock: suppresses CG-007."""
    source = """
import threading

events = []
lock = threading.Lock()

def worker(item):
    with lock:
        events.append(item)

t = threading.Thread(target=worker)
"""
    findings = _cg007(source)
    assert findings == []


def test_thread_shared_mutation_outside_with_lock_triggers_cg007() -> None:
    """Thread target mutating shared list outside with lock: triggers CG-007."""
    source = """
import threading

events = []

def worker(item):
    events.append(item)

t = threading.Thread(target=worker)
"""
    findings = _cg007(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "CG-007"


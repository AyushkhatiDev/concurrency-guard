"""Comprehensive test suite for ConcurrencyGuard v2.5.0 features.

Tests cover:
1. Structured concurrency (asyncio.TaskGroup, loop.create_task, anyio, BackgroundTasks)
2. Deadlock detection (CG-013 self-deadlocks, sync locks in async coroutines, RLock suppression)
3. SQLAlchemy 2.0 select().with_for_update() chain handling and LibCST patching
4. Git-diff aware scanning and pre-commit hook specification
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import yaml
from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.scanner.ast_rules import scan_source_code
from concurrency_guard.scanner.git_filter import get_changed_python_files

runner = CliRunner()


def test_asyncio_taskgroup_target_detection() -> None:
    code = """
import asyncio

cache = {}

async def worker(item):
    val = cache.get(item, 0)
    await asyncio.sleep(0.01)
    cache[item] = val + 1

async def main():
    async with asyncio.TaskGroup() as tg:
        tg.create_task(worker("a"))
"""
    findings = scan_source_code(code)
    rule_ids = {f.rule_id for f in findings}
    assert "CG-006" in rule_ids or "CG-008" in rule_ids


def test_asyncio_taskgroup_without_call_target() -> None:
    code = """
import asyncio

cache = {}

async def worker():
    val = cache.get("k", 0)
    await asyncio.sleep(0.01)
    cache["k"] = val + 1

async def main():
    async with asyncio.TaskGroup() as tg:
        tg.create_task(worker)
"""
    findings = scan_source_code(code)
    rule_ids = {f.rule_id for f in findings}
    assert "CG-006" in rule_ids or "CG-008" in rule_ids


def test_fastapi_background_tasks_target_detection() -> None:
    code = """
items = []

def worker():
    items.append(1)

def endpoint(background_tasks):
    background_tasks.add_task(worker)
"""
    findings = scan_source_code(code)
    rule_ids = {f.rule_id for f in findings}
    assert "CG-007" in rule_ids


def test_anyio_create_task_group_target_detection() -> None:
    code = """
import anyio

items = []

def worker():
    items.append(2)

async def main():
    async with anyio.create_task_group() as tg:
        tg.start_soon(worker)
"""
    findings = scan_source_code(code)
    rule_ids = {f.rule_id for f in findings}
    assert "CG-007" in rule_ids


def test_loop_create_task_detection() -> None:
    code = """
import asyncio

cache = {}

async def worker():
    val = cache.get("k", 0)
    await asyncio.sleep(0.01)
    cache["k"] = val + 1

async def main():
    loop = asyncio.get_event_loop()
    loop.create_task(worker())
"""
    findings = scan_source_code(code)
    rule_ids = {f.rule_id for f in findings}
    assert "CG-006" in rule_ids or "CG-008" in rule_ids


def test_intra_function_self_deadlock_sync_lock() -> None:
    code = """
import threading

lock = threading.Lock()

def bad_func():
    with lock:
        with lock:
            pass
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) >= 1
    assert any("self-deadlock" in f.message.lower() for f in cg13)


def test_intra_function_self_deadlock_async_lock() -> None:
    code = """
import asyncio

lock = asyncio.Lock()

async def bad_async_func():
    async with lock:
        async with lock:
            pass
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) >= 1
    assert any("self-deadlock" in f.message.lower() for f in cg13)


def test_intra_function_rlock_suppression() -> None:
    code = """
import threading

rlock = threading.RLock()

def safe_func():
    with rlock:
        with rlock:
            pass
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) == 0


def test_inter_procedural_self_deadlock() -> None:
    code = """
import threading

class Resource:
    def __init__(self):
        self.lock = threading.Lock()

    def parent(self):
        with self.lock:
            self.child()

    def child(self):
        with self.lock:
            print("nested")
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) >= 1
    assert any("self-deadlock" in f.message.lower() for f in cg13)


def test_inter_procedural_rlock_suppression() -> None:
    code = """
import threading

class Resource:
    def __init__(self):
        self.rlock = threading.RLock()

    def parent(self):
        with self.rlock:
            self.child()

    def child(self):
        with self.rlock:
            print("nested")
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) == 0


def test_sync_lock_in_async_def_without_await() -> None:
    code = """
import threading

lock = threading.Lock()

async def blocking_coro():
    with lock:
        x = 1
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) >= 1
    assert any("blocking synchronization" in f.message.lower() for f in cg13)


def test_sync_lock_in_async_def_across_await() -> None:
    code = """
import threading
import asyncio

lock = threading.Lock()

async def deadlocking_coro():
    with lock:
        await asyncio.sleep(0.1)
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) >= 1
    assert any("across 'await' boundary" in f.message.lower() or "event loop deadlock" in f.message.lower() for f in cg13)


def test_async_lock_in_async_def_safe() -> None:
    code = """
import asyncio

lock = asyncio.Lock()

async def safe_coro():
    async with lock:
        await asyncio.sleep(0.1)
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) == 0


def test_classic_lock_order_inversion_preserved() -> None:
    code = """
import threading

lock_a = threading.Lock()
lock_b = threading.Lock()

def worker1():
    with lock_a:
        with lock_b:
            pass

def worker2():
    with lock_b:
        with lock_a:
            pass
"""
    findings = scan_source_code(code)
    cg13 = [f for f in findings if f.rule_id == "CG-013"]
    assert len(cg13) >= 1
    assert any("reverse order" in f.message.lower() for f in cg13)


def test_sqlalchemy_select_where_with_for_update_suppressed() -> None:
    code = """
from sqlalchemy import select

async def update_balance(db, user_id):
    stmt = select(User).where(User.id == user_id).with_for_update()
    res = await db.execute(stmt)
    user = res.scalar_one()
    user.balance += 10
    await db.commit()
"""
    findings = scan_source_code(code)
    cg01 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg01) == 0


def test_sqlalchemy_select_with_for_update_where_suppressed() -> None:
    code = """
from sqlalchemy import select

async def update_balance(db, user_id):
    stmt = select(User).with_for_update().where(User.id == user_id)
    res = await db.execute(stmt)
    user = res.scalar_one()
    user.balance += 10
    await db.commit()
"""
    findings = scan_source_code(code)
    cg01 = [f for f in findings if f.rule_id == "CG-001"]
    assert len(cg01) == 0


def test_cst_fixer_session_execute_select_patch() -> None:
    code = """async def update_user(session, user_id):
    stmt = select(User).where(User.id == user_id)
    res = await session.execute(stmt)
    user = res.scalar_one()
    user.balance += 50
    await session.commit()
"""
    fixed = apply_all_fixes(code, rules={"CG-001"})
    assert ".with_for_update()" in fixed
    assert "select(User).where(User.id == user_id).with_for_update()" in fixed
    assert "session.execute(stmt).with_for_update()" not in fixed
    ast.parse(fixed)


def test_cst_fixer_session_scalar_select_patch() -> None:
    code = """async def update_user(session, user_id):
    user = await session.scalar(select(User).where(User.id == user_id))
    user.balance += 50
    await session.commit()
"""
    fixed = apply_all_fixes(code, rules={"CG-001"})
    assert "select(User).where(User.id == user_id).with_for_update()" in fixed
    assert "session.scalar" in fixed
    ast.parse(fixed)


def test_git_filter_changed_only(tmp_path: Path) -> None:
    # Initialize a temporary git repository
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True, check=True)

    file_a = tmp_path / "file_a.py"
    file_a.write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "file_a.py"], cwd=str(tmp_path), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    # Modify file_a and create file_b
    file_a.write_text("x = 2\n", encoding="utf-8")
    file_b = tmp_path / "file_b.py"
    file_b.write_text("y = 3\n", encoding="utf-8")

    changed = get_changed_python_files(tmp_path)
    assert file_a.resolve() in changed
    assert file_b.resolve() in changed


def test_cli_changed_only_flag(tmp_path: Path) -> None:
    file_clean = tmp_path / "clean.py"
    file_clean.write_text("def ok():\n    pass\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--changed-only", "--no-cache"])
    assert result.exit_code == 0


def test_pre_commit_hooks_yaml_validity() -> None:
    manifest_path = Path(".pre-commit-hooks.yaml")
    assert manifest_path.exists(), ".pre-commit-hooks.yaml must exist at repository root"
    content = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    assert isinstance(content, list)
    hook_ids = {h.get("id") for h in content if isinstance(h, dict)}
    assert "cguard-scan" in hook_ids
    assert "cguard-fix-diff" in hook_ids


def test_sdist_target_configuration() -> None:
    pyproject_text = Path("pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.hatch.build.targets.sdist]" in pyproject_text
    assert "/demo.gif" in pyproject_text
    assert "/website" in pyproject_text

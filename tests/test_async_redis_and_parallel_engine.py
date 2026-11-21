"""Tests for v3.7.0: Parse-Once Parallel Scan Engine + Asyncio/Redis Concurrency Rules (CG-025..027) + LibCST Auto-Fix."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.engine import ParsedModule, parse_modules_parallel
from concurrency_guard.patcher.cst_fixer import apply_all_fixes_with_report
from concurrency_guard.sarif import RULE_REGISTRY
from concurrency_guard.scanner.ast_rules import scan_project, scan_source_code


def test_cg_025_blocking_call_and_libcst_fix(tmp_path: Path) -> None:
    """Test CG-025: Blocking Call Inside async def and LibCST auto-fix."""
    code_with_blocking = """
import time
import requests
import subprocess
import urllib.request

async def handle_request():
    time.sleep(1)
    requests.get("https://api.example.com/data")
    urllib.request.urlopen("https://api.example.com")
    subprocess.run(["echo", "hello"])
"""
    findings = scan_source_code(code_with_blocking, filename="async_handler.py")
    cg025 = [f for f in findings if f.rule_id == "CG-025"]
    assert len(cg025) == 4
    messages = [f.message for f in cg025]
    assert any("time.sleep" in m for m in messages)
    assert any("requests.get" in m for m in messages)
    assert any("urllib.request.urlopen" in m for m in messages)
    assert any("subprocess.run" in m for m in messages)

    # Verify sanitizers (asyncio.to_thread, loop.run_in_executor, anyio.to_thread.run_sync)
    safe_code = """
import asyncio
import anyio
import requests
import time

async def safe_handler():
    loop = asyncio.get_running_loop()
    await asyncio.to_thread(time.sleep, 1)
    await asyncio.to_thread(requests.get, "https://api.example.com")
    await loop.run_in_executor(None, requests.get, "https://api.example.com")
    await anyio.to_thread.run_sync(requests.get, "https://api.example.com")
"""
    safe_findings = scan_source_code(safe_code, filename="safe_handler.py")
    assert not any(f.rule_id == "CG-025" for f in safe_findings)

    # Verify LibCST auto-fix transforms time.sleep() into await asyncio.sleep()
    target_code = """import time

async def worker():
    print("starting")
    time.sleep(0.5)
    print("done")
"""
    result = apply_all_fixes_with_report(target_code, rules={"CG-025"})
    assert result.modified is True
    assert "await asyncio.sleep(0.5)" in result.code
    assert "import asyncio" in result.code

    # Verify fixed code produces 0 CG-025 findings
    re_findings = scan_source_code(result.code, filename="worker.py")
    assert not any(f.rule_id == "CG-025" for f in re_findings)

    # CLI fix integration test
    test_file = tmp_path / "service.py"
    test_file.write_text(target_code, encoding="utf-8")
    runner = CliRunner()
    fix_res = runner.invoke(app, ["fix", str(test_file), "--write"])
    assert fix_res.exit_code == 0
    updated_content = test_file.read_text(encoding="utf-8")
    assert "await asyncio.sleep(0.5)" in updated_content
    assert "import asyncio" in updated_content


def test_cg_026_orphan_create_task() -> None:
    """Test CG-026: Unreferenced / Orphan Asyncio Background Task."""
    vulnerable_code = """
import asyncio

async def background_job():
    pass

async def dispatch_jobs(loop):
    asyncio.create_task(background_job())
    loop.create_task(background_job())
"""
    findings = scan_source_code(vulnerable_code, filename="tasks.py")
    cg026 = [f for f in findings if f.rule_id == "CG-026"]
    assert len(cg026) == 2
    assert all("orphan asyncio task" in f.message.lower() for f in cg026)

    # Verify safe variants where strong references or await are preserved
    safe_code = """
import asyncio

background_tasks = set()

async def safe_dispatch(loop):
    # 1. Assigned to variable
    task = asyncio.create_task(background_job())
    
    # 2. Stored in container/set
    background_tasks.add(asyncio.create_task(background_job()))
    
    # 3. Awaited directly
    await asyncio.create_task(background_job())
    
    # 4. Returned
    return loop.create_task(background_job())
"""
    safe_findings = scan_source_code(safe_code, filename="safe_tasks.py")
    assert not any(f.rule_id == "CG-026" for f in safe_findings)


def test_cg_027_redis_check_then_set_race() -> None:
    """Test CG-027: Non-Atomic Redis Check-Then-Set Race."""
    vulnerable_code = """
async def get_or_set(redis, key, val):
    existing = await redis.get(key)
    if not existing:
        await redis.set(key, val)
"""
    findings = scan_source_code(vulnerable_code, filename="cache.py")
    cg027 = [f for f in findings if f.rule_id == "CG-027"]
    assert len(cg027) == 1
    assert "non-atomic redis check-then-set race" in cg027[0].message.lower()

    # Safe variant 1: nx=True atomic set
    safe_nx = """
async def get_or_set(redis, key, val):
    existing = await redis.get(key)
    if not existing:
        await redis.set(key, val, nx=True)
"""
    findings_nx = scan_source_code(safe_nx, filename="safe_nx.py")
    assert not any(f.rule_id == "CG-027" for f in findings_nx)

    # Safe variant 2: Protected by distributed lock
    safe_lock = """
async def get_or_set(redis, key, val):
    async with redis.lock(f"lock:{key}"):
        existing = await redis.get(key)
        if not existing:
            await redis.set(key, val)
"""
    findings_lock = scan_source_code(safe_lock, filename="safe_lock.py")
    assert not any(f.rule_id == "CG-027" for f in findings_lock)

    # Safe variant 3: Redis transaction pipeline
    safe_pipeline = """
async def get_or_set(redis, key, val):
    async with redis.pipeline(transaction=True) as pipe:
        existing = await pipe.get(key)
        if not existing:
            await pipe.set(key, val)
"""
    findings_pipeline = scan_source_code(safe_pipeline, filename="safe_pipe.py")
    assert not any(f.rule_id == "CG-027" for f in findings_pipeline)


def test_parallel_scan_determinism(tmp_path: Path) -> None:
    """Test Parse-Once IR and parallel multi-core scanner determinism across 40 files."""
    code_template_vulnerable = """
import time
import asyncio

async def handler_{idx}():
    time.sleep(0.1)
    asyncio.create_task(handler_{idx}())
"""
    code_template_safe = """
async def safe_{idx}():
    pass
"""
    files: list[Path] = []
    for i in range(40):
        f = tmp_path / f"module_{i:02d}.py"
        if i % 2 == 0:
            f.write_text(code_template_vulnerable.format(idx=i), encoding="utf-8")
        else:
            f.write_text(code_template_safe.format(idx=i), encoding="utf-8")
        files.append(f)

    # Verify parse-once IR
    parsed_map = parse_modules_parallel(files, max_workers=4)
    assert len(parsed_map) == 40
    for pm in parsed_map.values():
        assert isinstance(pm, ParsedModule)
        assert pm.sha256 != ""
        assert pm.tree is not None

    # Scan sequentially (jobs=1) vs in parallel (jobs=4)
    findings_seq = scan_project(files, jobs=1)
    findings_par = scan_project(files, jobs=4)

    assert len(findings_seq) > 0
    assert len(findings_seq) == len(findings_par)

    # Verify byte-for-byte deterministic sort ordering
    seq_tuples = [(str(f.filename), f.lineno, f.rule_id, f.message) for f in findings_seq]
    par_tuples = [(str(f.filename), f.lineno, f.rule_id, f.message) for f in findings_par]
    assert seq_tuples == par_tuples


def test_sarif_rule_registry_v370() -> None:
    """Verify SARIF registry includes CG-025, CG-026, and CG-027 with proper CWE tags."""
    assert "CG-025" in RULE_REGISTRY
    assert "CG-026" in RULE_REGISTRY
    assert "CG-027" in RULE_REGISTRY

    cg025 = RULE_REGISTRY["CG-025"]
    assert "cwe-400" in cg025["properties"]["tags"]
    assert cg025["defaultConfiguration"]["level"] == "error"

    cg026 = RULE_REGISTRY["CG-026"]
    assert "cwe-662" in cg026["properties"]["tags"]
    assert cg026["defaultConfiguration"]["level"] == "warning"

    cg027 = RULE_REGISTRY["CG-027"]
    assert "cwe-362" in cg027["properties"]["tags"]
    assert cg027["defaultConfiguration"]["level"] == "error"

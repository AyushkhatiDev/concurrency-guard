"""Adversarial cache invalidation, corruption resilience, and parallel determinism test suite."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cache.file_cache import FileCache
from concurrency_guard.cli import app
from concurrency_guard.scanner.ast_rules import ASTFinding

runner = CliRunner()


def test_cache_hit_verification(tmp_path: Path) -> None:
    """Scanning a directory twice: run 1 populates cache; run 2 achieves 100% cache hits and identical findings."""
    cache_dir = tmp_path / ".cguard_cache"
    files: list[Path] = []
    for i in range(10):
        f = tmp_path / f"service_{i}.py"
        if i % 2 == 0:
            f.write_text(f"""
def transfer_{i}(amount):
    redis.delete("lock:service_{i}")
""", encoding="utf-8")
        else:
            f.write_text(f"""
def safe_read_{i}():
    return {i} * 42
""", encoding="utf-8")
        files.append(f)

    # Run 1: Cold scan populates cache
    res1 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res1.exit_code == 1
    data1 = json.loads(res1.stdout)
    assert data1["scanned_files"] == 10
    assert data1["cache_hits"] == 0
    assert data1["cache_misses"] == 10
    assert len(data1["findings"]) > 0

    # Run 2: Warm scan achieves 100% cache hits
    res2 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res2.exit_code == 1
    data2 = json.loads(res2.stdout)
    assert data2["scanned_files"] == 10
    assert data2["cache_hits"] == 10
    assert data2["cache_misses"] == 0
    assert data1["findings"] == data2["findings"]


def test_source_invalidation_single_file(tmp_path: Path) -> None:
    """Modifying a single character/comment in a file invalidates its cache while leaving other files cached."""
    cache_dir = tmp_path / ".cguard_cache"
    files: list[Path] = []
    for i in range(5):
        f = tmp_path / f"module_{i}.py"
        f.write_text(f"x_{i} = {i}\n", encoding="utf-8")
        files.append(f)

    # Initial scan populates cache for all 5 files
    res1 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res1.exit_code == 0
    data1 = json.loads(res1.stdout)
    assert data1["cache_hits"] == 0
    assert data1["cache_misses"] == 5

    # Second scan: 5 hits
    res2 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res2.exit_code == 0
    data2 = json.loads(res2.stdout)
    assert data2["cache_hits"] == 5

    # Modify module_0 by adding a comment
    files[0].write_text("x_0 = 0  # modified comment\n", encoding="utf-8")

    # Third scan: module_0 must miss, remaining 4 must hit
    res3 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res3.exit_code == 0
    data3 = json.loads(res3.stdout)
    assert data3["cache_hits"] == 4
    assert data3["cache_misses"] == 1


def test_flag_invalidation_ignore_pragma(tmp_path: Path) -> None:
    """Changing scan flags (--ignore-pragma) invalidates cache key and re-analyzes files."""
    cache_dir = tmp_path / ".cguard_cache"
    target = tmp_path / "pragmas.py"
    target.write_text("""
def update_score():
    redis.delete("lock:score")  # cguard: ignore[CG-018]
""", encoding="utf-8")

    # Run 1: with inline pragmas active (default) -> suppressed, findings = 0
    res1 = runner.invoke(app, ["scan", str(target), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res1.exit_code == 0
    data1 = json.loads(res1.stdout)
    assert data1["findings_count"] == 0

    # Run 2: with --ignore-pragma -> different cache key, finding reported!
    res2 = runner.invoke(app, ["scan", str(target), "--cache-dir", str(cache_dir), "--ignore-pragma", "--format", "json"])
    assert res2.exit_code == 1
    data2 = json.loads(res2.stdout)
    assert data2["findings_count"] == 1
    assert data2["findings"][0]["rule_id"] == "CG-018"


def test_cache_wipe_clear_cache(tmp_path: Path) -> None:
    """CLI flag --clear-cache wipes cache directory and forces cold scan."""
    cache_dir = tmp_path / ".cguard_cache"
    target = tmp_path / "worker.py"
    target.write_text("val = 1\n", encoding="utf-8")

    # Populate cache
    res1 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res1.exit_code == 0
    cache_entries = list(cache_dir.glob("*.json"))
    assert len(cache_entries) >= 1

    # Run with --clear-cache
    res2 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--clear-cache", "--format", "json"])
    assert res2.exit_code == 0
    data2 = json.loads(res2.stdout)
    # Since cache was wiped before scan, it was a cold scan
    assert data2["cache_misses"] >= 1


def test_parallel_determinism(tmp_path: Path) -> None:
    """Verifying --jobs 1 vs --jobs 4 produces 100% identical finding counts, order, and payloads."""
    files: list[Path] = []
    for i in range(12):
        f = tmp_path / f"job_test_{i:02d}.py"
        if i % 3 == 0:
            f.write_text(f"""
def r_delete_{i}():
    redis.delete("lock:job_{i}")

def bad_yield_{i}():
    with my_lock:
        yield {i}
""", encoding="utf-8")
        elif i % 3 == 1:
            f.write_text(f"""
def mutate_{i}():
    wallet.balance -= {i}
    wallet.save()
""", encoding="utf-8")
        else:
            f.write_text(f"""
def clean_func_{i}():
    return {i} * 2
""", encoding="utf-8")
        files.append(f)

    # Scan with --jobs 1
    res_single = runner.invoke(app, ["scan", str(tmp_path), "--jobs", "1", "--no-cache", "--format", "json"])
    data_single = json.loads(res_single.stdout)

    # Scan with --jobs 4
    res_multi = runner.invoke(app, ["scan", str(tmp_path), "--jobs", "4", "--no-cache", "--format", "json"])
    data_multi = json.loads(res_multi.stdout)

    assert res_single.exit_code == res_multi.exit_code
    assert data_single["findings_count"] == data_multi["findings_count"]
    assert len(data_single["findings"]) > 0

    # Ensure findings and ordering are 100% deterministic
    for f1, f2 in zip(data_single["findings"], data_multi["findings"]):
        assert f1["rule_id"] == f2["rule_id"]
        assert f1["filename"] == f2["filename"]
        assert f1["lineno"] == f2["lineno"]
        assert f1["function_name"] == f2["function_name"]


def test_corrupted_cache_entry_resilience(tmp_path: Path) -> None:
    """Corrupted cache file in .cguard_cache/ is gracefully purged and rebuilt without crashing."""
    cache_dir = tmp_path / ".cguard_cache"
    target = tmp_path / "corrupt_test.py"
    target.write_text("""
def bad_lock():
    redis.delete("lock:token")
""", encoding="utf-8")

    # Initial scan creates valid cache file
    res1 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res1.exit_code == 1
    json_files = list(cache_dir.glob("*.json"))
    assert len(json_files) == 1

    # Overwrite the cache file with corrupted / truncated JSON bytes
    json_files[0].write_bytes(b"{\"incomplete_json\": [TRUE, BAD_DATA...")

    # Second scan must not crash, must recover gracefully, and produce correct finding
    res2 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res2.exit_code == 1
    data2 = json.loads(res2.stdout)
    assert data2["findings_count"] == 1
    assert data2["findings"][0]["rule_id"] == "CG-018"
    assert data2["cache_misses"] == 1

    # Third scan should now be a clean cache hit
    res3 = runner.invoke(app, ["scan", str(tmp_path), "--cache-dir", str(cache_dir), "--format", "json"])
    assert res3.exit_code == 1
    data3 = json.loads(res3.stdout)
    assert data3["cache_hits"] == 1


def test_file_cache_direct_api(tmp_path: Path) -> None:
    """Direct unit tests for FileCache class methods and properties."""
    cache_dir = tmp_path / ".cguard_cache"
    cache = FileCache(cache_dir=cache_dir, version="2.9.0", ignore_pragma=False)

    f_path = tmp_path / "dummy.py"
    f_path.write_text("x = 42\n", encoding="utf-8")

    # Initial get: miss
    assert cache.get(f_path) is None
    assert cache.misses == 1
    assert cache.hits == 0

    # Set finding
    sample_finding = ASTFinding(
        rule_id="CG-001",
        filename=str(f_path),
        lineno=1,
        function_name="dummy",
        message="Sample message",
        suggested_fix_hint="Sample hint",
        confidence="HIGH",
        col_offset=4,
    )
    cache.set(f_path, [sample_finding])

    # Second get: hit
    retrieved = cache.get(f_path)
    assert retrieved is not None
    assert len(retrieved) == 1
    assert retrieved[0].rule_id == "CG-001"
    assert retrieved[0].col_offset == 4
    assert cache.hits == 1

    # Key changes if bytes change
    f_path.write_text("x = 43\n", encoding="utf-8")
    assert cache.get(f_path) is None
    assert cache.misses == 2

    # Clear cache wipes entries
    cleared = cache.clear()
    assert cleared >= 1
    assert not list(cache_dir.glob("*.json"))

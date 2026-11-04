"""Tests for SQLite-backed incremental scan caching engine."""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from concurrency_guard.cache.manager import (
    CacheManager,
    compute_cache_key,
    compute_rules_hash,
    dict_to_finding,
    finding_to_dict,
)
from concurrency_guard.cli import app
from concurrency_guard.scanner.ast_rules import ASTFinding, scan_file

runner = CliRunner()


def test_compute_cache_key_deterministic() -> None:
    """compute_cache_key must return a deterministic SHA-256 hash."""
    key1 = compute_cache_key(b"print('hello')", "2.2.0", "default_rules")
    key2 = compute_cache_key(b"print('hello')", "2.2.0", "default_rules")
    key3 = compute_cache_key(b"print('hello world')", "2.2.0", "default_rules")

    assert key1 == key2
    assert key1 != key3
    assert len(key1) == 64


def test_compute_rules_hash(tmp_path: Path) -> None:
    """compute_rules_hash handles default rules, custom lists, and YAML paths."""
    default_hash = compute_rules_hash()
    assert isinstance(default_hash, str) and len(default_hash) == 64

    custom_rules = [{"id": "CUSTOM-001", "function": "foo"}]
    custom_hash = compute_rules_hash(custom_rules=custom_rules)
    assert custom_hash != default_hash

    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("rules:\n  - id: R1\n", encoding="utf-8")
    file_hash = compute_rules_hash(rules_path=rule_file)
    assert file_hash != default_hash


def test_finding_dict_roundtrip() -> None:
    """finding_to_dict and dict_to_finding correctly serialize and reconstruct."""
    finding = ASTFinding(
        rule_id="CG-001",
        filename="app/wallet.py",
        lineno=42,
        function_name="withdraw",
        message="Unlocked read-modify-write",
        suggested_fix_hint="Use with_for_update()",
    )
    as_dict = finding_to_dict(finding)
    assert as_dict["rule_id"] == "CG-001"
    assert as_dict["lineno"] == 42

    reconstructed = dict_to_finding(as_dict)
    assert reconstructed.rule_id == finding.rule_id
    assert reconstructed.lineno == finding.lineno
    assert reconstructed.function_name == finding.function_name
    assert reconstructed.message == finding.message


def test_cache_hit_avoids_rescanning(tmp_path: Path) -> None:
    """Cache hit returns cached findings without re-scanning source code."""
    db_path = tmp_path / "cache.db"
    code_file = tmp_path / "target.py"
    code_file.write_text("async def test():\n    pass\n", encoding="utf-8")

    cm = CacheManager(cache_db_path=db_path, scanner_version="2.2.0", rules_hash="rules_v1")

    # Initial scan populates cache
    initial_findings = scan_file(code_file, cache_manager=cm)
    assert initial_findings == []

    # Inject a sentinel finding directly into cache to verify cache hit
    sentinel_finding = {
        "rule_id": "CG-SENTINEL",
        "filename": str(code_file),
        "lineno": 999,
        "function_name": "cached_fn",
        "message": "Loaded directly from cache",
        "suggested_fix_hint": "No re-scan occurred",
    }
    cm.update_cache(code_file, [sentinel_finding])

    # Second scan must return cached finding without invoking scan_source_code
    with patch("concurrency_guard.scanner.ast_rules.scan_source_code") as mock_scan:
        cached_results = scan_file(code_file, cache_manager=cm)
        mock_scan.assert_not_called()
        assert len(cached_results) == 1
        assert cached_results[0].rule_id == "CG-SENTINEL"
        assert cached_results[0].message == "Loaded directly from cache"


def test_cache_miss_when_file_content_changes(tmp_path: Path) -> None:
    """Cache miss occurs when the file content is modified."""
    db_path = tmp_path / "cache.db"
    code_file = tmp_path / "target.py"
    code_file.write_text("balance = 100\n", encoding="utf-8")

    cm = CacheManager(cache_db_path=db_path, scanner_version="2.2.0", rules_hash="rules_v1")

    findings = [{"rule_id": "CG-001", "filename": str(code_file), "lineno": 1, "function_name": "", "message": "", "suggested_fix_hint": ""}]
    cm.update_cache(code_file, findings)

    # Initial read is a hit
    cached = cm.get_cached_findings(code_file)
    assert cached is not None
    assert len(cached) == 1

    # Modify file content
    code_file.write_text("balance = 200\n", encoding="utf-8")

    # Cache miss expected
    assert cm.get_cached_findings(code_file) is None


def test_cache_miss_when_scanner_version_changes(tmp_path: Path) -> None:
    """Cache miss occurs when the scanner version changes."""
    db_path = tmp_path / "cache.db"
    code_file = tmp_path / "target.py"
    code_file.write_text("def worker(): pass\n", encoding="utf-8")

    cm_v1 = CacheManager(cache_db_path=db_path, scanner_version="1.0.0", rules_hash="rules_v1")
    cm_v1.update_cache(code_file, [{"rule_id": "CG-001", "filename": str(code_file), "lineno": 1, "function_name": "worker", "message": "", "suggested_fix_hint": ""}])

    # Hit on v1.0.0
    assert cm_v1.get_cached_findings(code_file) is not None

    # Miss on v2.0.0
    cm_v2 = CacheManager(cache_db_path=db_path, scanner_version="2.0.0", rules_hash="rules_v1")
    assert cm_v2.get_cached_findings(code_file) is None


def test_cache_miss_when_rules_hash_changes(tmp_path: Path) -> None:
    """Cache miss occurs when the rules hash changes."""
    db_path = tmp_path / "cache.db"
    code_file = tmp_path / "target.py"
    code_file.write_text("def worker(): pass\n", encoding="utf-8")

    cm_r1 = CacheManager(cache_db_path=db_path, scanner_version="2.2.0", rules_hash="rule_config_A")
    cm_r1.update_cache(code_file, [{"rule_id": "CG-001", "filename": str(code_file), "lineno": 1, "function_name": "worker", "message": "", "suggested_fix_hint": ""}])

    assert cm_r1.get_cached_findings(code_file) is not None

    cm_r2 = CacheManager(cache_db_path=db_path, scanner_version="2.2.0", rules_hash="rule_config_B")
    assert cm_r2.get_cached_findings(code_file) is None


def test_graceful_recovery_from_corrupted_db(tmp_path: Path) -> None:
    """Corrupted database file is recovered automatically without crashing."""
    db_path = tmp_path / "corrupted.db"
    code_file = tmp_path / "target.py"
    code_file.write_text("x = 1\n", encoding="utf-8")

    # Write corrupt non-SQLite data to the database file
    db_path.write_bytes(b"INVALID SQLITE FILE DATA -- CORRUPTED HEADER")

    # Initializing CacheManager should not crash
    cm = CacheManager(cache_db_path=db_path, scanner_version="2.2.0", rules_hash="rules_v1")

    # Read should gracefully return None
    cached = cm.get_cached_findings(code_file)
    assert cached is None

    # Writing should succeed on the recreated clean database
    test_finding = [{"rule_id": "CG-001", "filename": str(code_file), "lineno": 1, "function_name": "test", "message": "msg", "suggested_fix_hint": "hint"}]
    cm.update_cache(code_file, test_finding)

    # Subsequent read should hit the clean database
    cached_again = cm.get_cached_findings(code_file)
    assert cached_again is not None
    assert len(cached_again) == 1
    assert cached_again[0]["rule_id"] == "CG-001"


def test_purging_missing_and_deleted_files(tmp_path: Path) -> None:
    """Purge removes deleted files and files omitted from the existing file set."""
    db_path = tmp_path / "cache.db"
    file1 = tmp_path / "file1.py"
    file2 = tmp_path / "file2.py"
    file3 = tmp_path / "file3.py"

    file1.write_text("a = 1\n", encoding="utf-8")
    file2.write_text("b = 2\n", encoding="utf-8")
    file3.write_text("c = 3\n", encoding="utf-8")

    cm = CacheManager(cache_db_path=db_path, scanner_version="2.2.0", rules_hash="rules_v1")
    cm.update_cache(file1, [{"rule_id": "CG-001", "filename": str(file1), "lineno": 1, "function_name": "", "message": "", "suggested_fix_hint": ""}])
    cm.update_cache(file2, [{"rule_id": "CG-002", "filename": str(file2), "lineno": 1, "function_name": "", "message": "", "suggested_fix_hint": ""}])
    cm.update_cache(file3, [{"rule_id": "CG-003", "filename": str(file3), "lineno": 1, "function_name": "", "message": "", "suggested_fix_hint": ""}])

    # Delete file2 from disk
    file2.unlink()

    # Purge with existing files [file1, file2] (file3 is omitted, file2 deleted from disk)
    cm.purge_stale_entries({file1, file2})

    # file1 must remain cached
    assert cm.get_cached_findings(file1) is not None
    # file2 was deleted from disk -> purged
    assert cm.get_cached_findings(file2) is None
    # file3 was not in the existing set -> purged
    assert cm.get_cached_findings(file3) is None


def test_clear_cache(tmp_path: Path) -> None:
    """clear_cache removes all entries from the cache."""
    db_path = tmp_path / "cache.db"
    code_file = tmp_path / "target.py"
    code_file.write_text("x = 10\n", encoding="utf-8")

    cm = CacheManager(cache_db_path=db_path, scanner_version="2.2.0", rules_hash="rules_v1")
    cm.update_cache(code_file, [{"rule_id": "CG-001", "filename": str(code_file), "lineno": 1, "function_name": "", "message": "", "suggested_fix_hint": ""}])
    assert cm.get_cached_findings(code_file) is not None

    cm.clear_cache()
    assert cm.get_cached_findings(code_file) is None


def test_thread_safety(tmp_path: Path) -> None:
    """Concurrent threads reading and writing to cache do not cause race conditions."""
    db_path = tmp_path / "concurrent_cache.db"
    cm = CacheManager(cache_db_path=db_path, scanner_version="2.2.0", rules_hash="rules_v1")

    files: list[Path] = []
    for i in range(10):
        f = tmp_path / f"worker_{i}.py"
        f.write_text(f"val = {i}\n", encoding="utf-8")
        files.append(f)

    def worker_task(idx: int) -> None:
        target_file = files[idx]
        for _ in range(5):
            findings = [{"rule_id": f"CG-{idx:03d}", "filename": str(target_file), "lineno": idx, "function_name": f"f_{idx}", "message": "msg", "suggested_fix_hint": "hint"}]
            cm.update_cache(target_file, findings)
            cached = cm.get_cached_findings(target_file)
            assert cached is not None
            assert len(cached) == 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker_task, i) for i in range(10)]
        for fut in concurrent.futures.as_completed(futures):
            fut.result()

    for idx, target_file in enumerate(files):
        cached = cm.get_cached_findings(target_file)
        assert cached is not None
        assert cached[0]["rule_id"] == f"CG-{idx:03d}"


def test_cli_cache_options(tmp_path: Path) -> None:
    """cguard scan supports --cache-path and --no-cache CLI flags."""
    cache_db = tmp_path / "custom_cli_cache.db"
    code_file = tmp_path / "app.py"
    code_file.write_text("x = 1\n", encoding="utf-8")

    # Run with custom cache path
    result = runner.invoke(app, ["scan", str(code_file), "--cache-path", str(cache_db)])
    assert result.exit_code == 0
    assert cache_db.exists()

    # Run with --no-cache
    result_no_cache = runner.invoke(app, ["scan", str(code_file), "--no-cache"])
    assert result_no_cache.exit_code == 0

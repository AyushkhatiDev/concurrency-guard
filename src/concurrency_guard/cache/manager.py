"""SQLite-backed thread-safe incremental scanning cache for Concurrency Guard."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

if TYPE_CHECKING:
    from concurrency_guard.scanner.ast_rules import ASTFinding

logger = logging.getLogger(__name__)

DEFAULT_CACHE_FILE = Path(".concurrency_guard_cache.db")


def compute_cache_key(file_bytes: bytes, scanner_version: str, rules_hash: str) -> str:
    """Compute SHA-256 hash based on: file_bytes + scanner_version + rules_config_hash."""
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    hasher.update(scanner_version.encode("utf-8"))
    hasher.update(rules_hash.encode("utf-8"))
    return hasher.hexdigest()


def compute_rules_hash(
    rules_path: Optional[Path] = None,
    custom_rules: Optional[list[dict[str, Any]]] = None,
) -> str:
    """Compute deterministic hash for rule configuration."""
    hasher = hashlib.sha256()
    if rules_path is not None and rules_path.is_file():
        try:
            hasher.update(rules_path.read_bytes())
            return hasher.hexdigest()
        except OSError:
            pass
    if custom_rules is not None:
        try:
            hasher.update(json.dumps(custom_rules, sort_keys=True).encode("utf-8"))
            return hasher.hexdigest()
        except (TypeError, ValueError):
            pass
    hasher.update(b"builtin_rules_default")
    return hasher.hexdigest()


def finding_to_dict(finding: Any) -> dict[str, Any]:
    """Convert an ASTFinding or finding-like object/dict to a JSON-serializable dict."""
    if isinstance(finding, dict):
        return finding
    return {
        "rule_id": getattr(finding, "rule_id", ""),
        "filename": getattr(finding, "filename", ""),
        "lineno": getattr(finding, "lineno", 0),
        "col_offset": getattr(finding, "col_offset", None),
        "function_name": getattr(finding, "function_name", ""),
        "message": getattr(finding, "message", ""),
        "suggested_fix_hint": getattr(finding, "suggested_fix_hint", ""),
        "confidence": getattr(finding, "confidence", "HIGH"),
        "end_lineno": getattr(finding, "end_lineno", None),
    }


def dict_to_finding(data: dict[str, Any]) -> ASTFinding:
    """Reconstruct an ASTFinding object from a cached dictionary."""
    from concurrency_guard.scanner.ast_rules import ASTFinding

    return ASTFinding(
        rule_id=str(data.get("rule_id", "")),
        filename=str(data.get("filename", "")),
        lineno=int(data.get("lineno", 0)),
        function_name=str(data.get("function_name", "")),
        message=str(data.get("message", "")),
        suggested_fix_hint=str(data.get("suggested_fix_hint", "")),
        confidence=str(data.get("confidence", "HIGH")),
        end_lineno=data.get("end_lineno"),
        col_offset=data.get("col_offset"),
    )


class CacheManager:
    """Thread-safe, SQLite-backed cache manager for AST scan findings."""

    def __init__(
        self,
        cache_db_path: Union[Path, str],
        scanner_version: str,
        rules_hash: str,
    ) -> None:
        self.cache_db_path = Path(cache_db_path)
        self.scanner_version = scanner_version
        self.rules_hash = rules_hash
        self._lock = threading.RLock()
        self._init_db()

    def _normalize_path(self, filepath: Path) -> str:
        """Return a normalized string path for cache lookup."""
        try:
            return str(filepath.resolve())
        except (OSError, RuntimeError):
            return str(filepath)

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Provide a thread-safe connection with proper timeout and cleanup."""
        if self.cache_db_path.parent != Path("."):
            self.cache_db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(self.cache_db_path),
            check_same_thread=False,
            timeout=30.0,
        )
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self, force: bool = False) -> None:
        """Initialize the SQLite database and create file_cache table."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS file_cache (
                            filepath TEXT PRIMARY KEY,
                            content_hash TEXT NOT NULL,
                            scan_results_json TEXT NOT NULL,
                            timestamp REAL NOT NULL
                        );
                        """
                    )
                    conn.commit()
            except (sqlite3.Error, OSError) as exc:
                if not force:
                    logger.warning(
                        "Cache database at '%s' is corrupted or unreadable (%s). Recreating clean cache.",
                        self.cache_db_path,
                        exc,
                    )
                    self._recreate_db()

    def _recreate_db(self) -> None:
        """Delete corrupted database files and reinitialize a clean cache."""
        with self._lock:
            for ext in ("", "-wal", "-shm", "-journal"):
                target = Path(f"{self.cache_db_path}{ext}")
                try:
                    if target.exists():
                        target.unlink()
                except OSError:
                    pass
            try:
                self._init_db(force=True)
            except (sqlite3.Error, OSError) as exc:
                logger.warning("Failed to recreate cache database at '%s': %s", self.cache_db_path, exc)

    def compute_content_hash(self, file_bytes: bytes) -> str:
        """Compute the content hash using current scanner version and rules hash."""
        return compute_cache_key(file_bytes, self.scanner_version, self.rules_hash)

    def get_cached_findings(self, filepath: Path) -> Optional[list[dict[str, Any]]]:
        """Retrieve cached findings for filepath if content and parameters match."""
        with self._lock:
            try:
                file_bytes = filepath.read_bytes()
            except OSError:
                return None

            content_hash = self.compute_content_hash(file_bytes)
            norm_path = self._normalize_path(filepath)

            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT content_hash, scan_results_json FROM file_cache WHERE filepath = ?",
                        (norm_path,),
                    )
                    row = cursor.fetchone()
                    if row is None and norm_path != str(filepath):
                        cursor.execute(
                            "SELECT content_hash, scan_results_json FROM file_cache WHERE filepath = ?",
                            (str(filepath),),
                        )
                        row = cursor.fetchone()

                    if row is not None:
                        cached_hash, results_json = row[0], row[1]
                        if cached_hash == content_hash:
                            loaded = json.loads(results_json)
                            if isinstance(loaded, list):
                                return [dict(item) for item in loaded if isinstance(item, dict)]
                        return None
            except (sqlite3.Error, OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "Cache read failed on '%s' (%s). Recreating clean cache.",
                    self.cache_db_path,
                    exc,
                )
                self._recreate_db()
                return None
            return None

    def update_cache(self, filepath: Path, findings: list[dict[str, Any]]) -> None:
        """Store or update the scan findings for filepath in the SQLite cache."""
        with self._lock:
            try:
                file_bytes = filepath.read_bytes()
            except OSError:
                return

            content_hash = self.compute_content_hash(file_bytes)
            norm_path = self._normalize_path(filepath)
            scan_results_json = json.dumps(findings)
            now = time.time()

            for attempt in range(2):
                try:
                    with self._get_connection() as conn:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO file_cache (filepath, content_hash, scan_results_json, timestamp)
                            VALUES (?, ?, ?, ?);
                            """,
                            (norm_path, content_hash, scan_results_json, now),
                        )
                        conn.commit()
                    break
                except (sqlite3.Error, OSError) as exc:
                    logger.warning(
                        "Cache write failed on '%s' (%s). Recreating clean cache.",
                        self.cache_db_path,
                        exc,
                    )
                    self._recreate_db()
                    if attempt == 1:
                        break

    def purge_stale_entries(self, existing_filepaths: set[Path]) -> None:
        """Purge cache entries for files that no longer exist or are not in existing_filepaths."""
        with self._lock:
            valid_paths = {self._normalize_path(p) for p in existing_filepaths} | {str(p) for p in existing_filepaths}
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT filepath FROM file_cache")
                    rows = cursor.fetchall()
                    stale_paths = [
                        row[0]
                        for row in rows
                        if row[0] not in valid_paths or not Path(row[0]).exists()
                    ]
                    if stale_paths:
                        cursor.executemany("DELETE FROM file_cache WHERE filepath = ?", [(p,) for p in stale_paths])
                        conn.commit()
            except (sqlite3.Error, OSError) as exc:
                logger.warning("Cache purge failed on '%s': %s", self.cache_db_path, exc)
                self._recreate_db()

    def clear_cache(self) -> None:
        """Clear all cached entries from the database."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute("DELETE FROM file_cache")
                    conn.commit()
            except (sqlite3.Error, OSError) as exc:
                logger.warning("Cache clear failed on '%s': %s", self.cache_db_path, exc)
                self._recreate_db()

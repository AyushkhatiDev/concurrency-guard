"""High-performance atomic content-addressable SHA-256 file cache for Concurrency Guard."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

from concurrency_guard import __version__
from concurrency_guard.atomic_io import atomic_write_text
from concurrency_guard.cache.manager import dict_to_finding, finding_to_dict

if TYPE_CHECKING:
    from concurrency_guard.scanner.ast_rules import ASTFinding

logger = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = Path(".cguard_cache")


def compute_cache_key(
    file_bytes: bytes,
    version: str = __version__,
    flags: Optional[dict[str, Any]] = None,
    rules_hash: Optional[str] = None,
    dependency_digest: Optional[str] = None,
) -> str:
    """Compute a deterministic SHA-256 cache key.

    Combines:
      - raw file bytes
      - cguard version string
      - active analyzer/suppression flags (e.g. ignore_pragma)
      - custom rules hash
      - imported module dependency digest (cross-file invalidation)
    """
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    hasher.update(b"\x00")
    hasher.update(version.encode("utf-8"))
    hasher.update(b"\x00")
    if flags:
        hasher.update(json.dumps(flags, sort_keys=True).encode("utf-8"))
    hasher.update(b"\x00")
    if rules_hash:
        hasher.update(rules_hash.encode("utf-8"))
    if dependency_digest:
        hasher.update(b"\x00")
        hasher.update(dependency_digest.encode("utf-8"))
    return hasher.hexdigest()


class FileCache:
    """Deterministic, corruption-resistant content-addressable local file cache.

    Stores cached AST findings as atomic JSON files inside ``.cguard_cache/``.
    """

    def __init__(
        self,
        cache_dir: Union[Path, str] = DEFAULT_CACHE_DIR,
        version: str = __version__,
        ignore_pragma: bool = False,
        rules_hash: str = "",
        enabled: bool = True,
    ) -> None:
        self.cache_dir = Path(cache_dir).absolute()
        self._cache_root = self.cache_dir.resolve()
        self.version = version
        self.ignore_pragma = ignore_pragma
        self.rules_hash = rules_hash
        self.enabled = enabled
        self._lock = threading.RLock()
        self._hits: int = 0
        self._misses: int = 0

    @property
    def flags(self) -> dict[str, Any]:
        """Dictionary of flags that affect scan outcomes."""
        return {
            "ignore_pragma": self.ignore_pragma,
        }

    @property
    def hits(self) -> int:
        """Number of cache hits during this session."""
        with self._lock:
            return self._hits

    @property
    def misses(self) -> int:
        """Number of cache misses during this session."""
        with self._lock:
            return self._misses

    def get_cache_key(self, file_bytes: bytes, dependency_digest: Optional[str] = None) -> str:
        """Compute the content-addressable SHA-256 key for a byte sequence."""
        return compute_cache_key(
            file_bytes=file_bytes,
            version=self.version,
            flags=self.flags,
            rules_hash=self.rules_hash,
            dependency_digest=dependency_digest,
        )

    def _entry(self, key: str) -> Optional[Path]:
        try:
            if self.cache_dir.resolve() != self._cache_root or self.cache_dir.is_symlink():
                return None
            target = self.cache_dir / f"{key}.json"
            if target.is_symlink() or not target.resolve().is_relative_to(self._cache_root):
                return None
            return target
        except (OSError, RuntimeError):
            return None

    def get(self, filepath: Path, dependency_digest: Optional[str] = None) -> Optional[list[ASTFinding]]:
        """Retrieve cached findings for filepath if SHA-256 digest matches.

        Returns None on cache miss, cache disabled, or file read/corruption error.
        """
        if not self.enabled:
            return None

        try:
            file_bytes = filepath.read_bytes()
        except OSError:
            return None

        key = self.get_cache_key(file_bytes, dependency_digest=dependency_digest)
        cache_file = self._entry(key)

        if cache_file is None or not cache_file.is_file():
            with self._lock:
                self._misses += 1
            return None

        try:
            raw_text = cache_file.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            if isinstance(data, list):
                findings = [dict_to_finding(item) for item in data if isinstance(item, dict)]
                with self._lock:
                    self._hits += 1
                return findings
        except (json.JSONDecodeError, OSError, ValueError, KeyError) as exc:
            logger.debug("Corrupted cache entry at '%s' (%s). Purging entry.", cache_file, exc)
            try:
                cache_file.unlink(missing_ok=True)
            except OSError:
                pass

        with self._lock:
            self._misses += 1
        return None

    def set(
        self,
        filepath: Path,
        findings: list[ASTFinding],
        dependency_digest: Optional[str] = None,
    ) -> None:
        """Atomically persist scan findings into .cguard_cache/<sha256>.json."""
        if not self.enabled:
            return

        try:
            file_bytes = filepath.read_bytes()
        except OSError:
            return

        key = self.get_cache_key(file_bytes, dependency_digest=dependency_digest)

        try:
            target_file = self._entry(key)
            if target_file is None:
                return
            self.cache_dir.mkdir(parents=True, exist_ok=True)

            payload = json.dumps([finding_to_dict(f) for f in findings])
            atomic_write_text(target_file, payload)
        except OSError as exc:
            logger.debug("Failed atomic cache write for '%s' (%s).", filepath, exc)

    def get_cached_findings(
        self,
        filepath: Path,
        dependency_digest: Optional[str] = None,
    ) -> Optional[list[dict[str, Any]]]:
        """Duck-typing compatibility with CacheManager."""
        res = self.get(filepath, dependency_digest=dependency_digest)
        if res is None:
            return None
        return [finding_to_dict(f) for f in res]

    def update_cache(
        self,
        filepath: Path,
        findings: list[Any],
        dependency_digest: Optional[str] = None,
    ) -> None:
        """Duck-typing compatibility with CacheManager."""
        from concurrency_guard.scanner.ast_rules import ASTFinding

        converted = [f if isinstance(f, ASTFinding) else dict_to_finding(f) for f in findings]
        self.set(filepath, converted, dependency_digest=dependency_digest)

    def clear(self) -> int:
        """Cleanly remove all cached files in the cache directory."""
        with self._lock:
            count = 0
            if self._entry("clear") is None or not self.cache_dir.exists():
                return 0
            for item in list(self.cache_dir.iterdir()):
                try:
                    if item.is_file() or item.is_symlink():
                        item.unlink()
                        count += 1
                    elif item.is_dir():
                        shutil.rmtree(item)
                        count += 1
                except OSError:
                    pass
            self._hits = 0
            self._misses = 0
            return count

"""Cache subsystem for incremental AST scanning."""

from concurrency_guard.cache.file_cache import (
    DEFAULT_CACHE_DIR,
    FileCache,
)
from concurrency_guard.cache.file_cache import (
    compute_cache_key as compute_file_cache_key,
)
from concurrency_guard.cache.manager import (
    DEFAULT_CACHE_FILE,
    CacheManager,
    compute_cache_key,
    compute_rules_hash,
    dict_to_finding,
    finding_to_dict,
)

__all__ = [
    "DEFAULT_CACHE_DIR",
    "DEFAULT_CACHE_FILE",
    "CacheManager",
    "FileCache",
    "compute_cache_key",
    "compute_file_cache_key",
    "compute_rules_hash",
    "dict_to_finding",
    "finding_to_dict",
]


"""cguard.baseline alias for concurrency_guard.baseline."""

from concurrency_guard.baseline import (
    Baseline,
    BaselineEntry,
    BaselineFilterResult,
    compute_finding_fingerprint,
    create_baseline,
    filter_with_baseline,
    get_finding_source_snippet,
    normalize_relative_path,
    update_baseline_file,
)

__all__ = [
    "Baseline",
    "BaselineEntry",
    "BaselineFilterResult",
    "compute_finding_fingerprint",
    "create_baseline",
    "filter_with_baseline",
    "get_finding_source_snippet",
    "normalize_relative_path",
    "update_baseline_file",
]

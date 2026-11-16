"""cguard package alias for concurrency_guard."""

from concurrency_guard import __version__
from concurrency_guard.baseline import (
    Baseline,
    BaselineEntry,
    BaselineFilterResult,
    compute_finding_fingerprint,
    create_baseline,
    filter_with_baseline,
    update_baseline_file,
)
from concurrency_guard.sarif import findings_to_sarif, serialize_sarif

__all__ = [
    "Baseline",
    "BaselineEntry",
    "BaselineFilterResult",
    "__version__",
    "compute_finding_fingerprint",
    "create_baseline",
    "filter_with_baseline",
    "findings_to_sarif",
    "serialize_sarif",
    "update_baseline_file",
]

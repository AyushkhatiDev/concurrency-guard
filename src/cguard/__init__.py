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
from concurrency_guard.simulator import (
    AnomalyProof,
    ExecutionStep,
    InterleavingTrace,
    TimelineEvent,
    extract_execution_steps,
    generate_pytest_reproducer,
    simulate_finding,
)

__all__ = [
    "AnomalyProof",
    "Baseline",
    "BaselineEntry",
    "BaselineFilterResult",
    "ExecutionStep",
    "InterleavingTrace",
    "TimelineEvent",
    "__version__",
    "compute_finding_fingerprint",
    "create_baseline",
    "extract_execution_steps",
    "filter_with_baseline",
    "findings_to_sarif",
    "generate_pytest_reproducer",
    "serialize_sarif",
    "simulate_finding",
    "update_baseline_file",
]

"""cguard.simulator alias for concurrency_guard.simulator."""

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
    "ExecutionStep",
    "InterleavingTrace",
    "TimelineEvent",
    "extract_execution_steps",
    "generate_pytest_reproducer",
    "simulate_finding",
]

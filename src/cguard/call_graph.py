"""cguard.call_graph alias for concurrency_guard.call_graph."""

from concurrency_guard.call_graph import (
    CallGraph,
    CallSite,
    FunctionNode,
    FunctionSummary,
    analyze_module_functions,
    build_call_graph,
    build_module_function_summaries,
)

__all__ = [
    "CallGraph",
    "CallSite",
    "FunctionNode",
    "FunctionSummary",
    "analyze_module_functions",
    "build_call_graph",
    "build_module_function_summaries",
]

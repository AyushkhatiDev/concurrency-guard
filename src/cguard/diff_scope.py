"""Public alias for Git diff scan scoping."""

from concurrency_guard.diff_scope import changed_python_paths, impacted_python_paths

__all__ = ["changed_python_paths", "impacted_python_paths"]

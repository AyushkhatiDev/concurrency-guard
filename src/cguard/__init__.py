"""cguard package alias for concurrency_guard."""

from concurrency_guard import __version__
from concurrency_guard.sarif import findings_to_sarif, serialize_sarif

__all__ = ["__version__", "findings_to_sarif", "serialize_sarif"]

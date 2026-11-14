"""Concurrency Guard package."""

import sys

__version__ = "2.12.0"

# Register alias 'cguard' pointing to this package
sys.modules.setdefault("cguard", sys.modules[__name__])

from concurrency_guard import call_graph, sarif

sys.modules.setdefault("cguard.sarif", sarif)
sys.modules.setdefault("cguard.call_graph", call_graph)
cguard_module = sys.modules.get("cguard")
if cguard_module is not None:
    setattr(cguard_module, "sarif", sarif)  # noqa: B010
    setattr(cguard_module, "call_graph", call_graph)  # noqa: B010



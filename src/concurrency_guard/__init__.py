"""Concurrency Guard package."""

import sys

__version__ = "2.10.0"

# Register alias 'cguard' pointing to this package
sys.modules.setdefault("cguard", sys.modules[__name__])

from concurrency_guard import sarif

sys.modules.setdefault("cguard.sarif", sarif)
cguard_module = sys.modules.get("cguard")
if cguard_module is not None:
    setattr(cguard_module, "sarif", sarif)  # noqa: B010



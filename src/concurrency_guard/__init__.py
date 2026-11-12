"""Concurrency Guard package."""

import sys

__version__ = "2.8.0"

# Register alias 'cguard' pointing to this package
sys.modules.setdefault("cguard", sys.modules[__name__])



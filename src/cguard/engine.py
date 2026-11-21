"""Alias module for concurrency_guard.engine."""

import sys

from concurrency_guard import engine

sys.modules[__name__] = engine


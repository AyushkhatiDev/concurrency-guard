"""Alias module for concurrency_guard.report."""

import sys

from concurrency_guard import report

sys.modules[__name__] = report

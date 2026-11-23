"""Concurrency Guard package."""

import sys

__version__ = "3.9.2"

# Register alias 'cguard' pointing to this package
sys.modules.setdefault("cguard", sys.modules[__name__])

from concurrency_guard import (
    baseline,
    call_graph,
    config,
    engine,
    gh_review,
    lsp,
    project_graph,
    report,
    sarif,
    simulator,
    watch,
)

sys.modules.setdefault("cguard.sarif", sarif)
sys.modules.setdefault("cguard.call_graph", call_graph)
sys.modules.setdefault("cguard.config", config)
sys.modules.setdefault("cguard.baseline", baseline)
sys.modules.setdefault("cguard.simulator", simulator)
sys.modules.setdefault("cguard.gh_review", gh_review)
sys.modules.setdefault("cguard.lsp", lsp)
sys.modules.setdefault("cguard.watch", watch)
sys.modules.setdefault("cguard.project_graph", project_graph)
sys.modules.setdefault("cguard.engine", engine)
sys.modules.setdefault("cguard.report", report)
cguard_module = sys.modules.get("cguard")
if cguard_module is not None:
    setattr(cguard_module, "sarif", sarif)  # noqa: B010
    setattr(cguard_module, "call_graph", call_graph)  # noqa: B010
    setattr(cguard_module, "config", config)  # noqa: B010
    setattr(cguard_module, "baseline", baseline)  # noqa: B010
    setattr(cguard_module, "simulator", simulator)  # noqa: B010
    setattr(cguard_module, "gh_review", gh_review)  # noqa: B010
    setattr(cguard_module, "lsp", lsp)  # noqa: B010
    setattr(cguard_module, "watch", watch)  # noqa: B010
    setattr(cguard_module, "project_graph", project_graph)  # noqa: B010
    setattr(cguard_module, "engine", engine)  # noqa: B010
    setattr(cguard_module, "report", report)  # noqa: B010



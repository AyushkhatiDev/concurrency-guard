"""SDK for explicitly trusted, workspace-local Python rules."""
from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from concurrency_guard.engine import ParsedModule
    from concurrency_guard.scanner.ast_rules import ASTFinding


class CGuardRulePlugin(Protocol):
    rule_id: str
    severity: str
    cwe: str

    def check(self, module: ParsedModule) -> list[ASTFinding]: ...


class PluginError(ValueError):
    """A configured plugin cannot be loaded or executed."""


def load_plugins(root: Path, paths: list[str]) -> list[CGuardRulePlugin]:
    from concurrency_guard.sarif import RULE_REGISTRY

    root = root.resolve()
    result: list[CGuardRulePlugin] = []
    used_ids = set(RULE_REGISTRY)
    for relative in paths:
        supplied = Path(relative)
        try:
            path = (root / supplied).resolve(strict=True)
            if supplied.is_absolute() or not path.is_relative_to(root) or path.suffix != ".py":
                raise PluginError("expected a workspace-relative Python file")
            name = "_cguard_plugin_" + hashlib.sha256(str(path).encode()).hexdigest()
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise PluginError("could not create a Python module spec")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
            finally:
                del sys.modules[name]
            plugin: CGuardRulePlugin = module.PLUGIN
            if not re.fullmatch(r"[A-Z0-9][A-Z0-9_.-]{0,127}", plugin.rule_id) or plugin.rule_id in used_ids:
                raise PluginError("invalid or duplicate rule_id")
            if plugin.severity not in {"HIGH", "MEDIUM", "LOW"}:
                raise PluginError("severity must be HIGH, MEDIUM, or LOW")
            if not re.fullmatch(r"CWE-[1-9][0-9]*", plugin.cwe):
                raise PluginError("cwe must be a CWE identifier such as CWE-362")
            if not callable(plugin.check):
                raise PluginError("PLUGIN.check must be callable")
            used_ids.add(plugin.rule_id)
            result.append(plugin)
        except Exception as exc:
            raise PluginError(f"Failed to load rule plugin {relative!r}: {exc}") from exc
    return result

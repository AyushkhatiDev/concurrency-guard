"""Unified TOML configuration engine for Concurrency Guard.

Supports discovery and loading from:
1. .cguard.toml (highest priority)
2. cguard.toml
3. pyproject.toml [tool.cguard] / [tool.concurrency-guard]
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import-not-found]


DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".venv",
    "venv",
    "env",
    ".env",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "migrations",
    "alembic",
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".eggs",
    ".cguard_cache",
})


@dataclass
class CGuardConfig:
    """Unified configuration options for Concurrency Guard."""

    select: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    confidence: str = "low"
    jobs: Optional[int] = None
    custom_lock_names: list[str] = field(default_factory=list)
    per_file_ignores: dict[str, list[str]] = field(default_factory=dict)
    rules_file: Optional[str] = None
    cache: bool = True
    config_source: Optional[Path] = None

    def deterministic_hash(self) -> str:
        """Compute stable SHA-256 digest of active configuration for caching."""
        normalized = {
            "select": sorted(s.upper() for s in self.select),
            "ignore": sorted(i.upper() for i in self.ignore),
            "exclude": sorted(self.exclude),
            "confidence": self.confidence.lower(),
            "jobs": self.jobs,
            "custom_lock_names": sorted(self.custom_lock_names),
            "per_file_ignores": {
                k: sorted(r.upper() for r in v)
                for k, v in sorted(self.per_file_ignores.items())
            },
            "rules_file": self.rules_file,
            "cache": self.cache,
        }
        raw_bytes = json.dumps(normalized, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()

    def is_rule_enabled(
        self,
        rule_id: str,
        file_path: Optional[Union[str, Path]] = None,
        root_dir: Optional[Union[str, Path]] = None,
    ) -> bool:
        """Check if a rule is enabled for a given file and active configuration."""
        rid = rule_id.upper()
        # 1. Whitelist check (select)
        if self.select:
            selected_set = {s.upper() for s in self.select}
            if rid not in selected_set:
                return False

        # 2. Global blacklist check (ignore)
        if self.ignore:
            ignored_set = {i.upper() for i in self.ignore}
            if rid in ignored_set:
                return False

        # 3. Per-file ignores check
        if file_path and self.per_file_ignores:
            file_str = str(file_path).replace("\\", "/")
            base_name = Path(file_path).name
            rel_str = file_str
            if root_dir:
                try:
                    rel_str = str(Path(file_path).resolve().relative_to(Path(root_dir).resolve())).replace("\\", "/")
                except ValueError:
                    pass

            for pattern, ignored_rules in self.per_file_ignores.items():
                norm_pat = pattern.replace("\\", "/")
                if (
                    fnmatch.fnmatch(rel_str, norm_pat)
                    or fnmatch.fnmatch(file_str, norm_pat)
                    or fnmatch.fnmatch(base_name, norm_pat)
                    or fnmatch.fnmatch(rel_str, f"*/{norm_pat.lstrip('/')}")
                    or fnmatch.fnmatch(rel_str, f"{norm_pat.rstrip('/')}/*")
                ):
                    rule_set = {r.upper() for r in ignored_rules}
                    if rid in rule_set:
                        return False

        return True

    def is_path_excluded(
        self,
        path: Union[str, Path],
        root_dir: Optional[Union[str, Path]] = None,
    ) -> bool:
        """Check if a file or directory path is excluded."""
        path_obj = Path(path)
        path_str = str(path_obj).replace("\\", "/")
        rel_str = path_str
        if root_dir:
            try:
                rel_str = str(path_obj.resolve().relative_to(Path(root_dir).resolve())).replace("\\", "/")
            except ValueError:
                pass

        parts = set(path_obj.parts)
        if any(part in DEFAULT_EXCLUDED_DIRS for part in parts):
            return True

        for pattern in self.exclude:
            norm_pat = pattern.replace("\\", "/")
            if norm_pat in parts:
                return True
            if (
                fnmatch.fnmatch(rel_str, norm_pat)
                or fnmatch.fnmatch(path_str, norm_pat)
                or fnmatch.fnmatch(path_obj.name, norm_pat)
                or fnmatch.fnmatch(rel_str, f"*/{norm_pat.lstrip('/')}")
                or fnmatch.fnmatch(rel_str, f"{norm_pat.rstrip('/')}/*")
            ):
                return True

        return False


# Legacy alias
ProjectConfig = CGuardConfig


def _extract_cguard_table(data: dict[str, Any], is_pyproject: bool) -> Optional[dict[str, Any]]:
    """Extract cguard configuration table from parsed TOML data."""
    if is_pyproject:
        tool = data.get("tool")
        if isinstance(tool, dict):
            cguard = tool.get("cguard", tool.get("concurrency-guard"))
            if isinstance(cguard, dict):
                return cguard
        return None

    # Dedicated .cguard.toml or cguard.toml
    if "cguard" in data and isinstance(data["cguard"], dict):
        return data["cguard"]
    if "tool" in data and isinstance(data["tool"], dict):
        tool = data["tool"]
        cguard = tool.get("cguard", tool.get("concurrency-guard"))
        if isinstance(cguard, dict):
            return cguard
    # Root level keys
    return data


def find_config_file(start: Union[str, Path]) -> Optional[Path]:
    """Find the nearest configuration file walking upward from start path.

    Discovery Priority:
    1. .cguard.toml
    2. cguard.toml
    3. pyproject.toml (containing [tool.cguard] or [tool.concurrency-guard])
    """
    path_obj = Path(start).resolve()
    directory = path_obj if path_obj.is_dir() else path_obj.parent

    for candidate in (directory, *directory.parents):
        # 1. .cguard.toml
        dot_cguard = candidate / ".cguard.toml"
        if dot_cguard.is_file():
            return dot_cguard

        # 2. cguard.toml
        plain_cguard = candidate / "cguard.toml"
        if plain_cguard.is_file():
            return plain_cguard

        # 3. pyproject.toml with cguard section
        pyproject = candidate / "pyproject.toml"
        if pyproject.is_file():
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
                tool = data.get("tool")
                if isinstance(tool, dict) and ("cguard" in tool or "concurrency-guard" in tool):
                    return pyproject
            except (OSError, ValueError):
                pass

    return None


def parse_toml_config(file_path: Path) -> CGuardConfig:
    """Parse a TOML configuration file into a CGuardConfig instance."""
    try:
        content = file_path.read_text(encoding="utf-8")
        data = tomllib.loads(content)
    except Exception as exc:
        raise ValueError(f"Failed to parse config file '{file_path}': {exc}") from exc

    is_pyproject = file_path.name == "pyproject.toml"
    raw = _extract_cguard_table(data, is_pyproject=is_pyproject) or {}

    select_val = raw.get("select", [])
    select_list = [str(x).upper() for x in select_val] if isinstance(select_val, list) else []

    ignore_val = raw.get("ignore", [])
    ignore_list = [str(x).upper() for x in ignore_val] if isinstance(ignore_val, (list, set, tuple)) else []

    exclude_val = raw.get("exclude", [])
    exclude_list = [str(x) for x in exclude_val] if isinstance(exclude_val, (list, tuple)) else []

    confidence = str(raw.get("confidence", "low")).lower()

    jobs_val = raw.get("jobs")
    jobs = int(jobs_val) if jobs_val is not None and str(jobs_val).isdigit() else None

    custom_locks_val = raw.get("custom_lock_names", [])
    custom_locks = [str(x) for x in custom_locks_val] if isinstance(custom_locks_val, list) else []

    per_file_raw = raw.get("per_file_ignores", {})
    per_file_ignores: dict[str, list[str]] = {}
    if isinstance(per_file_raw, dict):
        for pat, rules in per_file_raw.items():
            if isinstance(rules, list):
                per_file_ignores[str(pat)] = [str(r).upper() for r in rules]
            elif isinstance(rules, str):
                per_file_ignores[str(pat)] = [rules.upper()]

    rules_file = str(raw["rules_file"]) if raw.get("rules_file") else None
    cache = bool(raw.get("cache", True))

    return CGuardConfig(
        select=select_list,
        ignore=ignore_list,
        exclude=exclude_list,
        confidence=confidence,
        jobs=jobs,
        custom_lock_names=custom_locks,
        per_file_ignores=per_file_ignores,
        rules_file=rules_file,
        cache=cache,
        config_source=file_path,
    )


def load_cguard_config(
    start_path: Optional[Union[str, Path]] = None,
    config_path: Optional[Union[str, Path]] = None,
) -> CGuardConfig:
    """Load CGuardConfig from explicit config path or discover from start_path."""
    if config_path is not None:
        explicit_path = Path(config_path).resolve()
        if not explicit_path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        return parse_toml_config(explicit_path)

    start = Path(start_path) if start_path is not None else Path.cwd()
    discovered = find_config_file(start)
    if discovered is not None:
        return parse_toml_config(discovered)

    return CGuardConfig()


def load_project_config(
    start: Path,
    config_path: Optional[Path] = None,
) -> CGuardConfig:
    """Legacy compatibility loader mapping directly to load_cguard_config."""
    return load_cguard_config(start_path=start, config_path=config_path)


__all__ = [
    "DEFAULT_EXCLUDED_DIRS",
    "CGuardConfig",
    "ProjectConfig",
    "find_config_file",
    "load_cguard_config",
    "load_project_config",
    "parse_toml_config",
]

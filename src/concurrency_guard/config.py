"""Project configuration loading for the command line interface."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # pragma: no cover - exercised on supported Python versions
    from tomllib import loads  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    from tomli import loads  # type: ignore[import-not-found]


@dataclass(frozen=True)
class ProjectConfig:
    exclude: tuple[str, ...] = ()
    ignore: frozenset[str] = frozenset()
    rules_file: str | None = None
    cache: bool = True


def load_project_config(start: Path) -> ProjectConfig:
    """Load the closest ``pyproject.toml`` tool.cguard configuration."""
    directory = start if start.is_dir() else start.parent
    for candidate in (directory, *directory.parents):
        config_path = candidate / "pyproject.toml"
        if not config_path.is_file():
            continue
        data: dict[str, Any] = loads(config_path.read_text(encoding="utf-8"))
        tool = data.get("tool", {})
        raw = tool.get("concurrency-guard", tool.get("cguard", {}))
        if not isinstance(raw, dict):
            return ProjectConfig()
        return ProjectConfig(
            exclude=tuple(str(value) for value in raw.get("exclude", [])),
            ignore=frozenset(str(value) for value in raw.get("ignore", [])),
            rules_file=str(raw["rules_file"]) if raw.get("rules_file") else None,
            cache=bool(raw.get("cache", True)),
        )
    return ProjectConfig()

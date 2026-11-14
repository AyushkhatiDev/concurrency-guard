"""cguard.config alias for concurrency_guard.config."""

from concurrency_guard.config import (
    DEFAULT_EXCLUDED_DIRS,
    CGuardConfig,
    ProjectConfig,
    find_config_file,
    load_cguard_config,
    load_project_config,
    parse_toml_config,
)

__all__ = [
    "DEFAULT_EXCLUDED_DIRS",
    "CGuardConfig",
    "ProjectConfig",
    "find_config_file",
    "load_cguard_config",
    "load_project_config",
    "parse_toml_config",
]

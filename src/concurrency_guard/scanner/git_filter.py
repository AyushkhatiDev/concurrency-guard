"""Git-diff aware file filtering for changed-only scans."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


def get_changed_python_files(
    repo_root: Path,
    base_ref: Optional[str] = None,
) -> set[Path]:
    """Return set of modified/added Python files using git."""
    changed: set[Path] = set()
    directory = repo_root.resolve() if repo_root.is_dir() else repo_root.parent.resolve()

    # Find git repository root
    git_root = directory
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(directory),
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            git_root = Path(res.stdout.strip()).resolve()
    except (OSError, subprocess.SubprocessError):
        pass

    def _run_git(args: list[str]) -> list[str]:
        try:
            res = subprocess.run(
                ["git", *args],
                cwd=str(git_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                return [line.strip() for line in res.stdout.splitlines() if line.strip()]
        except (OSError, subprocess.SubprocessError):
            pass
        return []

    # 1. Base-ref comparison if requested (e.g. origin/main...HEAD)
    if base_ref:
        lines = _run_git(["diff", "--name-only", "--diff-filter=ACMRTUXB", f"{base_ref}...HEAD"])
        if not lines:
            lines = _run_git(["diff", "--name-only", "--diff-filter=ACMRTUXB", base_ref])
        for line in lines:
            if line.endswith(".py"):
                p = (git_root / line).resolve()
                if p.is_file():
                    changed.add(p)

    # 2. Uncommitted changes relative to HEAD
    lines_head = _run_git(["diff", "--name-only", "--diff-filter=ACMRTUXB", "HEAD"])
    for line in lines_head:
        if line.endswith(".py"):
            p = (git_root / line).resolve()
            if p.is_file():
                changed.add(p)

    # 3. Staged / untracked files from git status --porcelain
    status_lines = _run_git(["status", "--porcelain"])
    for line in status_lines:
        parts = line.split()
        if len(parts) >= 2:
            candidate = parts[-1]
            if candidate.endswith(".py"):
                p = (git_root / candidate).resolve()
                if p.is_file():
                    changed.add(p)

    return changed

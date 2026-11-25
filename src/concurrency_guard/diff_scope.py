"""Scope committed Git changes to Python files and their transitive importers."""
from __future__ import annotations

import os
import subprocess
from collections import defaultdict, deque
from pathlib import Path

from concurrency_guard.project_graph import ProjectSymbolGraph


def _git(directory: Path, *args: str) -> bytes:
    try:
        return subprocess.run(
            ("git", "-C", str(directory), *args), check=True, capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise ValueError(exc.stderr.decode(errors="replace").strip() or "Git command failed") from exc
    except OSError as exc:
        raise ValueError(f"Could not run Git: {exc}") from exc


def changed_python_paths(directory: Path, ref: str) -> set[Path]:
    root = Path(os.fsdecode(_git(directory, "rev-parse", "--show-toplevel")).rstrip("\n")).resolve()
    commit = _git(directory, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").decode().strip()
    changes = _git(directory, "diff", "--no-renames", "--name-only", "-z", f"{commit}...HEAD", "--")
    return {
        (root / os.fsdecode(name)).absolute()
        for name in changes.split(b"\0") if name.endswith(b".py")
    }


def impacted_python_paths(
    directory: Path, ref: str, candidates: list[Path], graph: ProjectSymbolGraph,
) -> set[Path]:
    changed = changed_python_paths(directory, ref)
    reverse: dict[Path, set[Path]] = defaultdict(set)
    for path in candidates:
        source = path.resolve()
        for imported in graph.get_imported_files(source):
            reverse[imported].add(source)
    impacted = set(changed)
    pending = deque(changed)
    while pending:
        for caller in reverse[pending.popleft()] - impacted:
            impacted.add(caller)
            pending.append(caller)
    return {path.resolve() for path in candidates} & impacted

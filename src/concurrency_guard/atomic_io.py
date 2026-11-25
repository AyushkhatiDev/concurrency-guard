"""Atomic replacement for UTF-8 source files and scan artifacts."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from tempfile import NamedTemporaryFile


def atomic_write_text(target: Path, content: str) -> None:
    """Write and synchronize a sibling temporary file before replacing the target."""
    target = target.resolve(strict=False)
    try:
        mode = stat.S_IMODE(target.stat().st_mode)
    except FileNotFoundError:
        mode = None

    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            if mode is not None:
                os.chmod(temporary, mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

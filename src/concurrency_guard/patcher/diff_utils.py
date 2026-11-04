"""In-memory unified diff generation with preflight AST syntax validation."""

from __future__ import annotations

import ast
import difflib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from concurrency_guard.patcher.cst_fixer import PatchResult, PatchSkip

logger = logging.getLogger(__name__)


def validate_patch_syntax(patched_code: str) -> bool:
    """Preflight validation: parse source string with ast.parse to ensure valid Python."""
    try:
        ast.parse(patched_code)
        return True
    except (SyntaxError, ValueError) as exc:
        logger.error("Preflight syntax validation failed on generated patch: %s", exc)
        return False


def generate_unified_diff(
    original_code: str,
    patched_code: str,
    filepath: Union[Path, str] = "file.py",
    fromfile: Optional[str] = None,
    tofile: Optional[str] = None,
) -> str:
    """Generate standard unified diff between original and patched code in memory."""
    file_str = str(filepath)
    from_header = fromfile or f"a/{file_str}"
    to_header = tofile or f"b/{file_str}"

    diff_lines = list(
        difflib.unified_diff(
            original_code.splitlines(keepends=True),
            patched_code.splitlines(keepends=True),
            fromfile=from_header,
            tofile=to_header,
        )
    )
    return "".join(diff_lines)


def colorize_diff(diff_text: str, is_tty: bool = True) -> str:
    """Apply ANSI colors to unified diff (red for '-', green for '+') if is_tty is True."""
    if not is_tty or not diff_text:
        return diff_text

    colored_lines: list[str] = []
    for line in diff_text.splitlines(keepends=True):
        ending = "\n" if line.endswith("\n") else ""
        content = line.rstrip("\r\n")

        if content.startswith(("+++", "---")):
            colored_lines.append(f"\033[1m{content}\033[0m{ending}")
        elif content.startswith("+"):
            colored_lines.append(f"\033[32m{content}\033[0m{ending}")
        elif content.startswith("-"):
            colored_lines.append(f"\033[31m{content}\033[0m{ending}")
        elif content.startswith("@@"):
            colored_lines.append(f"\033[36m{content}\033[0m{ending}")
        else:
            colored_lines.append(line)
    return "".join(colored_lines)


@dataclass(frozen=True)
class DiffResult:
    """Result of an in-memory diff generation and preflight check."""

    original_code: str
    patched_code: str
    diff: str
    is_valid: bool
    error_message: Optional[str] = None
    skipped: tuple[PatchSkip, ...] = ()


class DiffGenerator:
    """Generates non-destructive, AST preflight-validated unified diffs in memory."""

    def __init__(
        self,
        rules: Optional[set[str]] = None,
        patch_fn: Optional[Callable[[str], Union[str, PatchResult]]] = None,
    ) -> None:
        self.rules = rules
        self.patch_fn = patch_fn

    def generate_diff(
        self,
        source_code: str,
        filepath: Union[Path, str] = "file.py",
        fromfile: Optional[str] = None,
        tofile: Optional[str] = None,
    ) -> DiffResult:
        """Apply patch strictly in memory, validate with ast.parse, and return unified diff."""
        file_str = str(filepath)
        skipped: tuple[PatchSkip, ...] = ()

        try:
            if self.patch_fn is not None:
                raw_result = self.patch_fn(source_code)
                if isinstance(raw_result, str):
                    patched_code = raw_result
                else:
                    patched_code = getattr(raw_result, "code", str(raw_result))
                    skipped = getattr(raw_result, "skipped", ())
            else:
                from concurrency_guard.patcher.cst_fixer import apply_all_fixes_with_report

                patch_result = apply_all_fixes_with_report(source_code, rules=self.rules)
                patched_code = patch_result.code
                skipped = patch_result.skipped
        except (SyntaxError, ValueError) as exc:
            logger.error("Preflight syntax validation failed on patch for '%s': %s", file_str, exc)
            return DiffResult(
                original_code=source_code,
                patched_code="",
                diff="",
                is_valid=False,
                error_message=str(exc),
            )

        # Preflight AST syntax validation on the resulting in-memory patched code
        if not validate_patch_syntax(patched_code):
            return DiffResult(
                original_code=source_code,
                patched_code="",
                diff="",
                is_valid=False,
                error_message="Invalid Python syntax produced by patcher",
                skipped=skipped,
            )

        diff = generate_unified_diff(
            source_code,
            patched_code,
            filepath=file_str,
            fromfile=fromfile,
            tofile=tofile,
        )

        return DiffResult(
            original_code=source_code,
            patched_code=patched_code,
            diff=diff,
            is_valid=True,
            error_message=None,
            skipped=skipped,
        )

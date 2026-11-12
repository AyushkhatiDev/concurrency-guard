"""Inline noise-suppression parser and filter for Concurrency Guard."""

from __future__ import annotations

import io
import re
import threading
import tokenize
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from concurrency_guard.scanner.ast_rules import ASTFinding

# Matches # cg:ignore, # cguard: ignore, # cg:ignore[CG-001], # cguard: ignore[CG-001, CG-002],
# # cg:ignore-start, # cguard: ignore-start, # cg:ignore-file, # cguard: ignore-file
# with optional rationale or comment suffix.
DIRECTIVE_RE = re.compile(
    r"^#\s*(?:cg|cguard)\s*:\s*(ignore-start|ignore-end|ignore-file|ignore)(?:\[([^\]]*)\])?(?:\s+.*)?$",
    re.IGNORECASE,
)


def parse_rules(raw_rules: Optional[str]) -> set[str]:
    """Parse comma-separated rule list into a set of uppercase rule IDs or wildcard '*'."""
    if raw_rules is None or not raw_rules.strip():
        return {"*"}
    parsed = {r.strip().upper() for r in raw_rules.split(",") if r.strip()}
    return parsed if parsed else {"*"}


def extract_comments_from_source(source_code: str) -> list[tuple[int, str]]:
    """Extract comment tokens with 1-based line numbers, ignoring string literals."""
    source_bytes = source_code.encode("utf-8")
    readline = io.BytesIO(source_bytes).readline
    comments: list[tuple[int, str]] = []
    try:
        for tok in tokenize.tokenize(readline):
            if tok.type == tokenize.COMMENT:
                comments.append((tok.start[0], tok.string))
    except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeDecodeError):
        pass
    return comments


@dataclass
class FileSuppressionRecord:
    """Internal suppression rules for a single source file."""

    file_rules: set[str] = field(default_factory=set)
    line_rules: dict[int, set[str]] = field(default_factory=dict)
    block_rules: list[tuple[int, int, set[str]]] = field(default_factory=list)


class SuppressionFilter:
    """Detects and applies # cg:ignore or # cguard: ignore suppression directives to scanner findings."""

    def __init__(self, ignore_pragma: bool = False) -> None:
        self.ignore_pragma: bool = ignore_pragma
        self.suppressed_count: int = 0
        self._file_records: dict[str, FileSuppressionRecord] = {}
        self._lock = threading.RLock()

    def _normalize_path(self, filepath: Union[Path, str]) -> str:
        p = Path(filepath)
        try:
            return str(p.resolve())
        except (OSError, RuntimeError):
            return str(p)

    def parse_source(
        self, source_code: str, filepath: Optional[Union[Path, str]] = None
    ) -> FileSuppressionRecord:
        """Parse source code comment tokens and build the suppression rule mapping."""
        comments = extract_comments_from_source(source_code)
        file_rules: set[str] = set()
        line_rules: dict[int, set[str]] = defaultdict(set)
        block_rules: list[tuple[int, int, set[str]]] = []
        open_blocks: dict[str, list[int]] = defaultdict(list)

        total_lines = len(source_code.splitlines()) or 1

        for line_no, comment_text in comments:
            m = DIRECTIVE_RE.match(comment_text.strip())
            if not m:
                continue

            directive = m.group(1).lower()
            rules = parse_rules(m.group(2))

            if directive == "ignore":
                line_rules[line_no].update(rules)
            elif directive == "ignore-file":
                file_rules.update(rules)
            elif directive == "ignore-start":
                for r in rules:
                    open_blocks[r].append(line_no)
            elif directive == "ignore-end":
                if rules == {"*"}:
                    for r, starts in list(open_blocks.items()):
                        while starts:
                            start_line = starts.pop()
                            block_rules.append((start_line, line_no, {r}))
                else:
                    for r in rules:
                        if open_blocks[r]:
                            start_line = open_blocks[r].pop()
                            block_rules.append((start_line, line_no, {r}))
                        elif open_blocks["*"]:
                            start_line = open_blocks["*"].pop()
                            block_rules.append((start_line, line_no, {r}))

        # Close unclosed blocks at end of file
        for r, starts in open_blocks.items():
            for start_line in starts:
                block_rules.append((start_line, total_lines, {r}))

        record = FileSuppressionRecord(
            file_rules=file_rules,
            line_rules=dict(line_rules),
            block_rules=block_rules,
        )

        if filepath is not None:
            norm = self._normalize_path(filepath)
            with self._lock:
                self._file_records[norm] = record
                self._file_records[str(filepath)] = record

        return record

    def parse_file(self, filepath: Path) -> FileSuppressionRecord:
        """Read and parse suppression directives for a file on disk."""
        try:
            source_code = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            source_code = ""
        return self.parse_source(source_code, filepath=filepath)

    def should_suppress(
        self,
        rule_id: str,
        filepath: Path,
        line_number: int,
        end_line_number: Optional[int] = None,
    ) -> bool:
        """Check if finding for rule_id on filepath:[line_number, end_line_number] is suppressed."""
        if self.ignore_pragma:
            return False

        norm_path = self._normalize_path(filepath)
        with self._lock:
            record = self._file_records.get(norm_path)
            if record is None:
                record = self._file_records.get(str(filepath))

        if record is None:
            if filepath.is_file():
                record = self.parse_file(filepath)
            else:
                return False

        rule_upper = rule_id.upper()

        # 1. File-level suppression
        if "*" in record.file_rules or rule_upper in record.file_rules:
            return True

        end_line = end_line_number if end_line_number is not None and end_line_number >= line_number else line_number

        # 2. Line-level suppression (checked across any line in the finding's span)
        for ln in range(line_number, end_line + 1):
            if ln in record.line_rules:
                target_rules = record.line_rules[ln]
                if "*" in target_rules or rule_upper in target_rules:
                    return True

        # 3. Block-level suppression (overlaps with [line_number, end_line])
        for start, end, block_rules in record.block_rules:
            if not (end < line_number or start > end_line) and ("*" in block_rules or rule_upper in block_rules):
                return True

        return False

    def filter_findings(
        self,
        findings: list[ASTFinding],
        file_path: Optional[Path] = None,
    ) -> list[ASTFinding]:
        """Filter findings using suppression rules and update suppressed_count."""
        if self.ignore_pragma:
            return list(findings)

        active: list[ASTFinding] = []
        for finding in findings:
            target_path = file_path if file_path is not None else Path(finding.filename)
            end_line = getattr(finding, "end_lineno", None)
            if self.should_suppress(finding.rule_id, target_path, finding.lineno, end_line):
                with self._lock:
                    self.suppressed_count += 1
            else:
                active.append(finding)
        return active

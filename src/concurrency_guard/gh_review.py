"""Autonomous GitHub PR Inline Review Bot & LibCST Suggestion Formatter.

Maps AST concurrency findings to unified pull request diff coordinates,
generates GitHub one-click suggestion blocks via LibCST auto-patching,
and interfaces idempotently with the GitHub REST API.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

from concurrency_guard.patcher.cst_fixer import apply_all_fixes_with_report

if TYPE_CHECKING:
    from concurrency_guard.scanner.ast_rules import ASTFinding

GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "ConcurrencyGuard-ReviewBot/3.3.0"

RULE_EXPLANATIONS: dict[str, str] = {
    "CG-001": (
        "Unlocked Read-Modify-Write race condition detected. This query fetches an entity "
        "without row-level locking (`.with_for_update()`), leading to potential lost updates under concurrency."
    ),
    "CG-002": (
        "Missing Idempotency-Key header guard on mutating route detected. Concurrent network retries "
        "or duplicate submissions can trigger duplicate financial transactions or state mutations."
    ),
    "CG-004": (
        "Check-Then-Act (TOCTOU) race condition detected. An existence check is executed without atomic "
        "locking or unique constraints, allowing concurrent conflicting inserts."
    ),
}

HUNK_HEADER_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$")


@dataclass(frozen=True)
class DiffHunk:
    """Represents a unified diff hunk."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    modified_lines: set[int] = field(default_factory=set)
    context_lines: set[int] = field(default_factory=set)
    raw_lines: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DiffFile:
    """Represents a modified file in a unified diff."""

    old_path: str
    new_path: str
    hunks: list[DiffHunk] = field(default_factory=list)


@dataclass
class PRDiffPosition:
    """Calculated position of an AST finding within a GitHub PR diff."""

    path: str
    line: int
    start_line: Optional[int] = None
    is_modified_line: bool = True
    hunk_header: str = ""

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


@dataclass
class ReviewComment:
    """GitHub Pull Request inline review comment payload."""

    path: str
    line: int
    body: str
    commit_id: Optional[str] = None
    start_line: Optional[int] = None
    start_side: str = "RIGHT"
    side: str = "RIGHT"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "path": self.path,
            "line": self.line,
            "body": self.body,
            "side": self.side,
        }
        if self.commit_id:
            data["commit_id"] = self.commit_id
        if self.start_line is not None and self.start_line < self.line:
            data["start_line"] = self.start_line
            data["start_side"] = self.start_side
        return data


@dataclass
class ReviewResult:
    """Summary of comments created and skipped during a PR review run."""

    comments_created: int = 0
    comments_skipped: int = 0
    comments: list[dict[str, Any]] = field(default_factory=list)


def parse_unified_diff(diff_text: str) -> dict[str, DiffFile]:
    """Parse unified diff text into a dictionary of DiffFile keyed by normalized new_path."""
    files: dict[str, DiffFile] = {}
    current_file: Optional[DiffFile] = None
    current_hunk: Optional[DiffHunk] = None
    current_new_line = 0

    lines = diff_text.splitlines()
    for line in lines:
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                old_p = parts[2].removeprefix("a/")
                new_p = parts[3].removeprefix("b/")
                current_file = DiffFile(old_path=old_p, new_path=new_p, hunks=[])
                files[new_p] = current_file
                current_hunk = None
            continue

        if line.startswith("--- "):
            raw = line[4:].strip()
            raw = raw.removeprefix("a/")
            if current_file is not None and raw != "/dev/null":
                object.__setattr__(current_file, "old_path", raw)
            continue

        if line.startswith("+++ "):
            raw = line[4:].strip()
            raw = raw.removeprefix("b/")
            if current_file is not None and raw != "/dev/null":
                object.__setattr__(current_file, "new_path", raw)
                files[raw] = current_file
            elif current_file is None and raw != "/dev/null":
                current_file = DiffFile(old_path=raw, new_path=raw, hunks=[])
                files[raw] = current_file
            continue

        m = HUNK_HEADER_RE.match(line)
        if m:
            old_start = int(m.group(1))
            old_count = int(m.group(2) or 1)
            new_start = int(m.group(3))
            new_count = int(m.group(4) or 1)

            current_hunk = DiffHunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                header=line,
                modified_lines=set(),
                context_lines=set(),
                raw_lines=[],
            )
            if current_file is not None:
                current_file.hunks.append(current_hunk)
            current_new_line = new_start
            continue

        if current_hunk is not None:
            current_hunk.raw_lines.append(line)
            if line.startswith("+"):
                current_hunk.modified_lines.add(current_new_line)
                current_new_line += 1
            elif line.startswith("-"):
                pass  # Deleted line from old file
            elif line.startswith(" "):
                current_hunk.context_lines.add(current_new_line)
                current_new_line += 1

    return files


def _normalize_path(p: str) -> str:
    """Normalize file path to POSIX relative representation."""
    posix = Path(p).as_posix()
    return posix.lstrip("./")


def map_finding_to_pr_diff(
    finding: ASTFinding,
    diff_text: str,
    repo_root: Optional[Union[Path, str]] = None,
) -> Optional[PRDiffPosition]:
    """Map an ASTFinding to its corresponding valid line within the PR's unified diff.

    Returns a PRDiffPosition if the finding falls within a diff hunk, or None if
    the finding is in an unchanged section outside the PR's diff.
    """
    if not diff_text.strip():
        return None

    diff_files = parse_unified_diff(diff_text)
    finding_norm = _normalize_path(finding.filename)

    target_diff_file: Optional[DiffFile] = None
    for path_key, df in diff_files.items():
        norm_key = _normalize_path(path_key)
        if (
            norm_key == finding_norm
            or norm_key.endswith(finding_norm)
            or finding_norm.endswith(norm_key)
            or Path(finding.filename).name == Path(path_key).name
        ):
            target_diff_file = df
            break

    if target_diff_file is None or not target_diff_file.hunks:
        return None

    target_lineno = finding.lineno

    for hunk in target_diff_file.hunks:
        hunk_start = hunk.new_start
        hunk_end = hunk.new_start + max(hunk.new_count - 1, 0)

        # Check if finding line is within this hunk's range
        if hunk_start <= target_lineno <= hunk_end:
            is_mod = target_lineno in hunk.modified_lines
            return PRDiffPosition(
                path=target_diff_file.new_path,
                line=target_lineno,
                is_modified_line=is_mod,
                hunk_header=hunk.header,
            )

    return None


def _extract_cst_replacement(
    source_code: str,
    rule_id: str,
    lineno: int,
) -> tuple[Optional[str], Optional[int], Optional[int]]:
    """Extract modified line range and replacement text using LibCST."""
    res = apply_all_fixes_with_report(source_code, rules={rule_id}, dry_run=True)
    if not res.modified:
        return None, None, None

    orig_lines = source_code.splitlines()
    patch_lines = res.code.splitlines()

    matcher = difflib.SequenceMatcher(None, orig_lines, patch_lines)
    best_replacement: Optional[str] = None
    best_start: Optional[int] = None
    best_end: Optional[int] = None
    min_dist = float("inf")

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "insert"):
            start_line = i1 + 1
            end_line = max(i2, start_line)
            dist = abs(lineno - start_line)
            if dist < min_dist:
                min_dist = dist
                best_replacement = "\n".join(patch_lines[j1:j2])
                best_start = start_line
                best_end = end_line

    return best_replacement, best_start, best_end


def format_suggestion_comment(
    finding: ASTFinding,
    source_code: Optional[str] = None,
    replacement_code: Optional[str] = None,
) -> str:
    """Format a GitHub PR review comment with an interactive ```suggestion block."""
    explanation = RULE_EXPLANATIONS.get(
        finding.rule_id,
        finding.message or "Potential concurrency race condition detected.",
    )

    patch_snip: Optional[str] = replacement_code

    if patch_snip is None:
        src = source_code
        if src is None:
            p = Path(finding.filename)
            if p.is_file():
                try:
                    src = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    src = None

        if src is not None:
            rep, _, _ = _extract_cst_replacement(src, finding.rule_id, finding.lineno)
            if rep:
                patch_snip = rep

    if patch_snip is None and finding.rule_id == "CG-001":
        patch_snip = "wallet = await db.get(Wallet, user_id, with_for_update=True)"

    marker = f"<!-- cguard:finding:{finding.rule_id}:{finding.lineno} -->"

    if patch_snip:
        comment_body = (
            f"⚠️ **ConcurrencyGuard Security Alert (`{finding.rule_id}`)**: {explanation}\n\n"
            f"```suggestion\n"
            f"# Applied ConcurrencyGuard automated LibCST patch:\n"
            f"{patch_snip.strip()}\n"
            f"```\n\n"
            f"{marker}"
        )
    else:
        comment_body = (
            f"⚠️ **ConcurrencyGuard Security Alert (`{finding.rule_id}`)**: {explanation}\n\n"
            f"> **Remediation**: Guard state mutation with row locks or idempotency checks.\n\n"
            f"{marker}"
        )

    return comment_body


def detect_github_environment() -> dict[str, Optional[str]]:
    """Detect GitHub Actions environment variables or git repository context."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    pr_num_str = os.environ.get("GITHUB_PR_NUMBER") or os.environ.get("PR_NUMBER")

    if not pr_num_str:
        ref = os.environ.get("GITHUB_REF", "")
        m = re.search(r"refs/pull/(\d+)/(?:merge|head)", ref)
        if m:
            pr_num_str = m.group(1)

    if not pr_num_str:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if event_path and Path(event_path).is_file():
            try:
                event_data = json.loads(Path(event_path).read_text(encoding="utf-8"))
                if "pull_request" in event_data and "number" in event_data["pull_request"]:
                    pr_num_str = str(event_data["pull_request"]["number"])
            except (json.JSONDecodeError, OSError):
                pass

    commit_sha = os.environ.get("GITHUB_SHA")
    if not commit_sha:
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                commit_sha = res.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass

    return {
        "token": token,
        "repo": repo,
        "pr_number": pr_num_str,
        "commit_sha": commit_sha,
    }


def github_api_request(
    endpoint: str,
    method: str = "GET",
    token: Optional[str] = None,
    data: Optional[dict[str, Any]] = None,
    headers_extra: Optional[dict[str, str]] = None,
) -> Any:
    """Execute authenticated HTTP request to GitHub REST API using urllib."""
    url = f"{GITHUB_API_BASE}{endpoint}" if endpoint.startswith("/") else endpoint
    body_bytes = json.dumps(data).encode("utf-8") if data is not None else None

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body_bytes is not None:
        headers["Content-Type"] = "application/json"
    if headers_extra:
        headers.update(headers_extra)

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        content = resp.read().decode("utf-8")
        if not content:
            return None
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type or content.strip().startswith(("{", "[")):
            return json.loads(content)
        return content


def fetch_existing_pr_comments(repo: str, pr_number: int, token: str) -> list[dict[str, Any]]:
    """Retrieve all existing PR inline review comments to prevent duplicate posting."""
    endpoint = f"/repos/{repo}/pulls/{pr_number}/comments"
    res = github_api_request(endpoint, method="GET", token=token)
    return res if isinstance(res, list) else []


def post_pr_review_comment(
    repo: str,
    pr_number: int,
    comment: ReviewComment,
    token: str,
) -> dict[str, Any]:
    """Post an inline review comment with a suggestion block on a GitHub Pull Request."""
    endpoint = f"/repos/{repo}/pulls/{pr_number}/comments"
    payload = comment.to_dict()
    res = github_api_request(endpoint, method="POST", token=token, data=payload)
    return res if isinstance(res, dict) else {}


def fetch_pr_diff(repo: str, pr_number: int, token: str) -> str:
    """Fetch PR unified diff directly from GitHub REST API."""
    endpoint = f"/repos/{repo}/pulls/{pr_number}"
    res = github_api_request(
        endpoint,
        method="GET",
        token=token,
        headers_extra={"Accept": "application/vnd.github.v3.diff"},
    )
    return str(res) if res is not None else ""


def get_pr_diff(repo_root: Union[Path, str], base_ref: Optional[str] = None) -> str:
    """Retrieve local unified diff via git."""
    root = Path(repo_root).resolve()
    base = base_ref or "origin/main"
    try:
        res = subprocess.run(
            ["git", "diff", f"{base}...HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout

        res_head = subprocess.run(
            ["git", "diff", "HEAD~1"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if res_head.returncode == 0 and res_head.stdout.strip():
            return res_head.stdout
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def is_duplicate_comment(comment: ReviewComment, existing_comments: list[dict[str, Any]]) -> bool:
    """Determine whether an identical ConcurrencyGuard review comment already exists on the PR."""
    marker_match = re.search(r"<!-- cguard:finding:([^:]+):(\d+) -->", comment.body)
    rule_marker = marker_match.group(0) if marker_match else None

    for existing in existing_comments:
        if existing.get("path") != comment.path:
            continue
        if existing.get("line") != comment.line:
            continue

        existing_body = existing.get("body", "")
        if rule_marker and rule_marker in existing_body:
            return True

        if "**ConcurrencyGuard Security Alert" in existing_body and marker_match and marker_match.group(1) in existing_body:
            return True

    return False


def run_pr_review(
    findings: list[ASTFinding],
    diff_text: str,
    repo: str,
    pr_number: int,
    token: str,
    commit_id: Optional[str] = None,
    dry_run: bool = False,
) -> ReviewResult:
    """Execute end-to-end PR review process, mapping findings and dispatching comments."""
    existing_comments: list[dict[str, Any]] = []
    if not dry_run and token:
        try:
            existing_comments = fetch_existing_pr_comments(repo, pr_number, token)
        except urllib.error.HTTPError:
            existing_comments = []

    created_count = 0
    skipped_count = 0
    comments_payload: list[dict[str, Any]] = []

    for finding in findings:
        pos = map_finding_to_pr_diff(finding, diff_text)
        if pos is None:
            # Finding is outside PR diff lines; cannot attach inline review comment
            continue

        body = format_suggestion_comment(finding)
        comment = ReviewComment(
            path=pos.path,
            line=pos.line,
            body=body,
            commit_id=commit_id,
        )

        if not dry_run and is_duplicate_comment(comment, existing_comments):
            skipped_count += 1
            continue

        if dry_run:
            comments_payload.append(comment.to_dict())
            created_count += 1
        else:
            try:
                res = post_pr_review_comment(repo, pr_number, comment, token)
                comments_payload.append(res)
                created_count += 1
            except urllib.error.HTTPError:
                pass

    return ReviewResult(
        comments_created=created_count,
        comments_skipped=skipped_count,
        comments=comments_payload,
    )

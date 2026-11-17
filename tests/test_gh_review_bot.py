"""Comprehensive test suite for ConcurrencyGuard GitHub PR Review Bot & LibCST Suggestion Formatter."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.gh_review import (
    ReviewComment,
    detect_github_environment,
    format_suggestion_comment,
    is_duplicate_comment,
    map_finding_to_pr_diff,
    parse_unified_diff,
)
from concurrency_guard.scanner.ast_rules import ASTFinding

runner = CliRunner()

SAMPLE_UNIFIED_DIFF = """diff --git a/app/routes.py b/app/routes.py
index 1234567..89abcdef 100644
--- a/app/routes.py
+++ b/app/routes.py
@@ -10,6 +10,8 @@ async def update_wallet(db, user_id: int, amount: float):
     stmt = select(Wallet).where(Wallet.user_id == user_id)
     wallet = await db.scalar(stmt)
+    wallet.balance += amount
+    await db.commit()
     return wallet
"""

SAMPLE_VULNERABLE_CODE = """from sqlalchemy import select

async def withdraw(db, user_id: int, amount: float):
    stmt = select(Wallet).where(Wallet.user_id == user_id)
    wallet = await db.scalar(stmt)
    wallet.balance -= amount
    await db.commit()
"""


def test_finding_to_diff_mapping() -> None:
    # Finding line 11 falls inside @@ -10,6 +10,8 @@ (lines 10..17 in new file)
    finding_in = ASTFinding(
        rule_id="CG-001",
        filename="app/routes.py",
        lineno=11,
        function_name="update_wallet",
        message="Unlocked read-modify-write",
        suggested_fix_hint="Add with_for_update()",
    )
    pos = map_finding_to_pr_diff(finding_in, SAMPLE_UNIFIED_DIFF)
    assert pos is not None
    assert pos.line == 11
    assert pos.path == "app/routes.py"
    assert pos["line"] == 11
    assert pos["path"] == "app/routes.py"

    # Finding at line 88 falls outside diff hunk
    finding_out = ASTFinding(
        rule_id="CG-001",
        filename="app/routes.py",
        lineno=88,
        function_name="other_func",
        message="Unlocked read-modify-write",
        suggested_fix_hint="Add with_for_update()",
    )
    pos_out = map_finding_to_pr_diff(finding_out, SAMPLE_UNIFIED_DIFF)
    assert pos_out is None

    # Finding in a file not touched by the diff
    finding_unrelated = ASTFinding(
        rule_id="CG-001",
        filename="app/models.py",
        lineno=10,
        function_name="model_func",
        message="Unlocked read-modify-write",
        suggested_fix_hint="Add with_for_update()",
    )
    assert map_finding_to_pr_diff(finding_unrelated, SAMPLE_UNIFIED_DIFF) is None


def test_format_suggestion_comment() -> None:
    finding = ASTFinding(
        rule_id="CG-001",
        filename="app/routes.py",
        lineno=5,
        function_name="withdraw",
        message="Unlocked Read-Modify-Write race condition detected.",
        suggested_fix_hint="Add with_for_update()",
    )

    # In-memory LibCST patch generation
    comment = format_suggestion_comment(finding, source_code=SAMPLE_VULNERABLE_CODE)
    assert "⚠️ **ConcurrencyGuard Security Alert (`CG-001`)" in comment
    assert "```suggestion" in comment
    assert "with_for_update()" in comment
    assert "<!-- cguard:finding:CG-001:5 -->" in comment

    # Explicit replacement override
    explicit_rep = "wallet = await db.get(Wallet, user_id, with_for_update=True)"
    comment_explicit = format_suggestion_comment(
        finding,
        source_code=SAMPLE_VULNERABLE_CODE,
        replacement_code=explicit_rep,
    )
    assert explicit_rep in comment_explicit
    assert "```suggestion" in comment_explicit


def test_dry_run_cli_execution() -> None:
    result = runner.invoke(
        app,
        ["gh-review", "--dry-run", "examples/vulnerable_wallet.py"],
    )
    assert result.exit_code == 0, f"Command failed: {result.output}"
    assert "ConcurrencyGuard PR Inline Review Bot (Dry-Run Mode)" in result.output
    assert "CG-001" in result.output
    assert "```suggestion" in result.output

    # Find the JSON block in stdout
    json_start = result.output.find("[")
    assert json_start != -1, "Expected JSON array in output"
    payload_str = result.output[json_start:]
    payload = json.loads(payload_str)
    assert isinstance(payload, list)
    assert len(payload) >= 1
    assert any("examples/vulnerable_wallet.py" in str(item.get("path")) for item in payload)


@patch("concurrency_guard.cli.fetch_pr_diff", return_value="")
@patch("concurrency_guard.cli.get_pr_diff", return_value="")
@patch("concurrency_guard.cli.post_pr_review_comment")
@patch("concurrency_guard.cli.fetch_existing_pr_comments")
def test_api_mocking_and_idempotency(
    mock_fetch_existing: MagicMock,
    mock_post_comment: MagicMock,
    mock_get_diff: MagicMock,
    mock_fetch_diff: MagicMock,
) -> None:
    # 1. First execution: no existing comments -> comments should be posted
    mock_fetch_existing.return_value = []
    mock_post_comment.return_value = {"id": 101, "body": "posted"}

    result1 = runner.invoke(
        app,
        [
            "gh-review",
            "examples/vulnerable_wallet.py",
            "--token",
            "mock-gh-token-12345",
            "--repo",
            "AyushkhatiDev/concurrency-guard",
            "--pr",
            "42",
        ],
    )
    assert result1.exit_code == 0, f"Execution 1 failed: {result1.output}"
    assert mock_post_comment.call_count >= 1

    # 2. Second execution: simulate identical comment already exists in PR
    mock_post_comment.reset_mock()
    mock_fetch_existing.return_value = [
        {
            "id": 101,
            "path": "examples/vulnerable_wallet.py",
            "line": 51,
            "body": (
                "⚠️ **ConcurrencyGuard Security Alert (`CG-001`)**: Unlocked Read-Modify-Write\n"
                "<!-- cguard:finding:CG-001:51 -->"
            ),
        },
        {
            "id": 102,
            "path": "examples/vulnerable_wallet.py",
            "line": 46,
            "body": (
                "⚠️ **ConcurrencyGuard Security Alert (`CG-002`)**: Missing Idempotency-Key\n"
                "<!-- cguard:finding:CG-002:46 -->"
            ),
        },
    ]

    result2 = runner.invoke(
        app,
        [
            "gh-review",
            "examples/vulnerable_wallet.py",
            "--token",
            "mock-gh-token-12345",
            "--repo",
            "AyushkhatiDev/concurrency-guard",
            "--pr",
            "42",
        ],
    )
    assert result2.exit_code == 0, f"Execution 2 failed: {result2.output}"
    # Duplicate comments must be skipped via idempotency check
    assert mock_post_comment.call_count == 0
    assert "Skipped (idempotent)" in result2.output


def test_missing_token_or_non_pr_graceful_fallback() -> None:
    # Ensure environment variables are not leaking
    clean_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp",
    }
    result = runner.invoke(
        app,
        ["gh-review", "examples/vulnerable_wallet.py"],
        env=clean_env,
    )
    assert result.exit_code == 0
    assert "Warning: GITHUB_TOKEN" in result.output
    assert "Skipping PR review comment posting" in result.output


def test_detect_github_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secrettoken999")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/88/merge")
    monkeypatch.setenv("GITHUB_SHA", "abcdef1234567890")

    env = detect_github_environment()
    assert env["token"] == "ghp_secrettoken999"
    assert env["repo"] == "org/repo"
    assert env["pr_number"] == "88"
    assert env["commit_sha"] == "abcdef1234567890"


def test_is_duplicate_comment() -> None:
    comment = ReviewComment(
        path="app/views.py",
        line=25,
        body="⚠️ **ConcurrencyGuard Security Alert (`CG-001`)**\n<!-- cguard:finding:CG-001:25 -->",
    )
    existing_match = [
        {"path": "app/views.py", "line": 25, "body": "Prior review <!-- cguard:finding:CG-001:25 -->"},
    ]
    assert is_duplicate_comment(comment, existing_match) is True

    existing_no_match = [
        {"path": "app/views.py", "line": 30, "body": "Different line"},
        {"path": "other.py", "line": 25, "body": "Different file"},
    ]
    assert is_duplicate_comment(comment, existing_no_match) is False


def test_parse_unified_diff_multiple_files() -> None:
    diff = """diff --git a/file1.py b/file1.py
--- a/file1.py
+++ b/file1.py
@@ -1,3 +1,4 @@
 a = 1
+b = 2
 c = 3
diff --git a/file2.py b/file2.py
--- a/file2.py
+++ b/file2.py
@@ -10,3 +10,4 @@
 x = 10
+y = 20
 z = 30
"""
    files = parse_unified_diff(diff)
    assert len(files) == 2
    assert "file1.py" in files
    assert "file2.py" in files
    assert len(files["file1.py"].hunks) == 1
    assert len(files["file2.py"].hunks) == 1
    assert files["file1.py"].hunks[0].new_start == 1
    assert files["file2.py"].hunks[0].new_start == 10

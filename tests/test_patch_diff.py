"""Tests for in-memory unified diff generation, AST preflight syntax validation, and CLI dry-run."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.patcher.diff_utils import (
    DiffGenerator,
    colorize_diff,
    generate_unified_diff,
    validate_patch_syntax,
)

runner = CliRunner()

VULNERABLE_WALLET_CODE = """from sqlalchemy import select

async def withdraw(db, user_id, amount):
    account = await db.scalar(select(Account).where(Account.id == user_id))
    account.balance -= amount
    await db.commit()
"""


def test_unified_diff_generation_matches_standard_format() -> None:
    """generate_unified_diff outputs standard git-style unified diff with headers and hunks."""
    original = "x = 1\ny = 2\n"
    patched = "x = 1\ny = 3\nz = 4\n"

    diff = generate_unified_diff(original, patched, filepath="module.py")

    assert diff.startswith("--- a/module.py")
    assert "+++ b/module.py" in diff
    assert "@@ -1,2 +1,3 @@" in diff
    assert "-y = 2" in diff
    assert "+y = 3" in diff
    assert "+z = 4" in diff


def test_dry_run_does_not_modify_file_on_disk(tmp_path: Path) -> None:
    """--dry-run outputs unified diff to stdout without modifying the physical file."""
    target_file = tmp_path / "wallet.py"
    target_file.write_text(VULNERABLE_WALLET_CODE, encoding="utf-8")

    # Run CLI fix with --dry-run
    result = runner.invoke(app, ["fix", str(target_file), "--dry-run"])

    assert result.exit_code == 0
    # Output must contain the unified diff
    assert ".with_for_update()" in result.stdout
    assert "---" in result.stdout
    assert "+++" in result.stdout

    # The file on disk must NOT be modified
    content_on_disk = target_file.read_text(encoding="utf-8")
    assert content_on_disk == VULNERABLE_WALLET_CODE
    assert ".with_for_update()" not in content_on_disk


def test_diff_flag_alias_behaves_identically_to_dry_run(tmp_path: Path) -> None:
    """--diff is an alias for --dry-run that produces unified diff and leaves file untouched."""
    target_file = tmp_path / "wallet.py"
    target_file.write_text(VULNERABLE_WALLET_CODE, encoding="utf-8")

    result = runner.invoke(app, ["fix", str(target_file), "--diff"])

    assert result.exit_code == 0
    assert ".with_for_update()" in result.stdout
    assert target_file.read_text(encoding="utf-8") == VULNERABLE_WALLET_CODE


def test_ast_preflight_validates_syntax() -> None:
    """validate_patch_syntax returns True for valid Python and False for invalid syntax."""
    valid_code = "def valid():\n    return 42\n"
    invalid_code = "def invalid(:\n    unbalanced = (1 +\n"

    assert validate_patch_syntax(valid_code) is True
    assert validate_patch_syntax(invalid_code) is False


def test_ast_preflight_rejects_simulated_invalid_patch(tmp_path: Path) -> None:
    """DiffGenerator rejects a patch if the transformation produces invalid Python syntax."""
    source_code = "def worker(): pass\n"

    # Simulate a patch transformer producing broken Python (unbalanced parentheses)
    broken_patch_fn = lambda code: code + "\ndef broken_fn(:\n    pass\n"

    diff_gen = DiffGenerator(patch_fn=broken_patch_fn)
    diff_result = diff_gen.generate_diff(source_code, filepath="worker.py")

    # Patch must be discarded, is_valid must be False, diff must be empty
    assert diff_result.is_valid is False
    assert diff_result.diff == ""
    assert diff_result.error_message is not None


def test_exit_code_contract_on_preflight_failure(tmp_path: Path) -> None:
    """CLI fix exits with code 1 and discards patch when preflight validation fails."""
    target_file = tmp_path / "target.py"
    target_file.write_text("def worker(): pass\n", encoding="utf-8")

    # Mock DiffGenerator to simulate an invalid patch output
    with patch("concurrency_guard.cli.DiffGenerator") as MockGen:
        instance = MockGen.return_value
        from concurrency_guard.patcher.diff_utils import DiffResult

        instance.generate_diff.return_value = DiffResult(
            original_code="def worker(): pass\n",
            patched_code="",
            diff="",
            is_valid=False,
            error_message="SyntaxError: invalid syntax (unbalanced parentheses)",
        )

        result = runner.invoke(app, ["fix", str(target_file), "--dry-run"])

        assert result.exit_code == 1
        assert "Preflight syntax validation failed" in result.stdout
        # File on disk remains untouched
        assert target_file.read_text(encoding="utf-8") == "def worker(): pass\n"


def test_colorize_diff_ansi_escapes() -> None:
    """colorize_diff applies ANSI codes when is_tty is True and leaves text unchanged when False."""
    diff_text = """--- a/test.py
+++ b/test.py
@@ -1,1 +1,1 @@
-old_val = 1
+new_val = 2
"""
    # Non-TTY mode: no ANSI escapes
    plain = colorize_diff(diff_text, is_tty=False)
    assert "\033[" not in plain
    assert plain == diff_text

    # TTY mode: contains ANSI escape codes for additions, deletions, headers, and chunks
    colored = colorize_diff(diff_text, is_tty=True)
    assert "\033[32m+new_val = 2\033[0m" in colored
    assert "\033[31m-old_val = 1\033[0m" in colored
    assert "\033[36m@@ -1,1 +1,1 @@\033[0m" in colored
    assert "\033[1m--- a/test.py\033[0m" in colored
    assert "\033[1m+++ b/test.py\033[0m" in colored

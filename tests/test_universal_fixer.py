"""LibCST remediation coverage for standard-library concurrency rules."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from concurrency_guard.cli import app
from concurrency_guard.patcher.cst_fixer import apply_all_fixes
from concurrency_guard.scanner.ast_rules import scan_source_code

runner = CliRunner()


def test_fix_write_wraps_thread_target_mutation_in_threading_lock(tmp_path: Path) -> None:
    """The CLI writes a lossless threading lock patch for a shared list mutation."""
    target = tmp_path / "race.py"
    target.write_text(
        "# Preserve this comment\nshared = []\n\ndef append_event(event):\n    shared.append(event)\n\nthread = threading.Thread(target=append_event)\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["fix", str(target), "--rule", "CG-007", "--write"])
    patched = target.read_text(encoding="utf-8")
    assert result.exit_code == 0
    assert "# Preserve this comment" in patched
    assert "import threading" in patched
    assert "with threading.Lock():" in patched
    assert not any(finding.rule_id == "CG-007" for finding in scan_source_code(patched))


def test_file_overwrite_fix_wraps_open_context_in_filelock() -> None:
    """A concurrent write-mode open remains intact inside a FileLock context."""
    code = '''
async def write_report(path, contents):
    # Keep the developer's file comment.
    with open(path, "w") as handle:
        handle.write(contents)
'''
    assert any(finding.rule_id == "CG-009" for finding in scan_source_code(code))

    patched = apply_all_fixes(code, rules={"CG-009"})

    assert "from filelock import FileLock" in patched
    assert "with FileLock(path + '.lock'):" in patched
    assert "with open(path, \"w\") as handle:" in patched
    assert "# Keep the developer's file comment." in patched
    assert not any(finding.rule_id == "CG-009" for finding in scan_source_code(patched))

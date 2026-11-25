"""Regression coverage for interrupted writes and malformed scanner input."""

from io import BytesIO
from pathlib import Path

import pytest

from concurrency_guard.atomic_io import atomic_write_text
from concurrency_guard.lsp import LanguageServer, encode_message
from concurrency_guard.scanner.ast_rules import discover_python_files, scan_directory


def test_interrupted_replace_preserves_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "source.py"
    target.write_text("before", encoding="utf-8")

    def interrupt(*args: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("concurrency_guard.atomic_io.os.replace", interrupt)
    with pytest.raises(KeyboardInterrupt):
        atomic_write_text(target, "after")
    assert target.read_text(encoding="utf-8") == "before"
    assert list(tmp_path.iterdir()) == [target]


def test_workspace_skips_symlink_files_and_malformed_python(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("pass", encoding="utf-8")
    (workspace / "link.py").symlink_to(outside)
    (workspace / "invalid.py").write_bytes(b"\xff")
    (workspace / "nested.py").write_text("x = " + "[" * 500 + "0" + "]" * 500, encoding="utf-8")
    (workspace / "null.py").write_bytes(b"x = 1\x00")
    assert len(discover_python_files(workspace)) == 3
    assert scan_directory(workspace) == []


def test_lsp_recovers_from_malformed_frames() -> None:
    incoming = BytesIO(
        b"Content-Length: -1\r\n\r\nContent-Length: 3\r\n\r\n[!]"
        + encode_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    )
    outgoing = BytesIO()
    LanguageServer(incoming, outgoing).run()
    assert outgoing.getvalue().count(b'"code":-32700') == 2
    assert b'"id":1' in outgoing.getvalue()

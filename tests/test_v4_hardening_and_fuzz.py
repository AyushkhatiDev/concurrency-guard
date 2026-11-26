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


def test_project_import_cannot_escape_explicit_root(tmp_path: Path) -> None:
    from concurrency_guard.project_graph import resolve_module_path

    workspace = tmp_path / "project"
    workspace.mkdir()
    outside = tmp_path / "external.py"
    outside.touch()
    (workspace / "linked.py").symlink_to(outside)

    assert resolve_module_path(workspace / "app.py", "linked", roots=[workspace]) is None
    assert resolve_module_path(workspace / "app.py", "external", 2, [workspace], {outside}) is None
    (workspace / "local.py").touch()
    assert resolve_module_path(workspace / "app.py", "local", roots=[workspace]) == workspace / "local.py"


def test_cache_does_not_overwrite_symlink_target(tmp_path: Path) -> None:
    from concurrency_guard.cache.file_cache import FileCache

    source = tmp_path / "source.py"
    source.write_text("pass", encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text("[]", encoding="utf-8")
    cache = FileCache(tmp_path / "cache")
    cache.cache_dir.mkdir()
    key = cache.get_cache_key(source.read_bytes())
    (cache.cache_dir / f"{key}.json").symlink_to(outside)

    assert cache.get(source) is None
    cache.set(source, [])
    assert outside.read_text(encoding="utf-8") == "[]"


def test_cfg_limits_emit_warning(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    import ast
    import sys

    from concurrency_guard.cfg import CFGLimitError, build_function_cfg

    function = ast.parse("def f():\n    if condition:\n        pass\n").body[0]
    assert isinstance(function, ast.FunctionDef)
    cfg_module = sys.modules[build_function_cfg.__module__]
    with monkeypatch.context() as patch:
        patch.setattr(cfg_module, "MAX_CFG_DEPTH", 1)
        with pytest.raises(CFGLimitError, match="nesting depth"):
            build_function_cfg(function)
    monkeypatch.setattr(cfg_module, "MAX_CFG_BLOCKS", 2)
    with pytest.raises(CFGLimitError, match="basic block"):
        build_function_cfg(function)
    assert "Skipping CFG" in caplog.text


def test_sarif_rejects_invalid_rule_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    from concurrency_guard.sarif import RULE_REGISTRY, findings_to_sarif
    from concurrency_guard.scanner.ast_rules import ASTFinding

    finding = ASTFinding("bad/id", "sample.py", 1, "f", "message", "hint")
    with pytest.raises(ValueError, match="identifier"):
        findings_to_sarif([finding])
    with monkeypatch.context() as patch:
        patch.setitem(RULE_REGISTRY["CG-001"], "defaultConfiguration", {"level": "critical"})
        with pytest.raises(ValueError, match="level"):
            findings_to_sarif([])
    monkeypatch.setitem(RULE_REGISTRY["CG-001"], "helpUri", "http://cwe.mitre.org/data/definitions/362.html")
    with pytest.raises(ValueError, match="CWE URI"):
        findings_to_sarif([])


def test_malformed_editor_params_do_not_stop_the_server() -> None:
    incoming = BytesIO(
        encode_message({"jsonrpc": "2.0", "id": 7, "method": "textDocument/codeAction", "params": []})
        + encode_message({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": None}})
        + encode_message({"jsonrpc": "2.0", "id": 8, "method": "initialize", "params": {}})
    )
    outgoing = BytesIO()
    LanguageServer(incoming, outgoing).run()
    assert outgoing.getvalue().count(b'"code":-32602') == 1
    assert b'"id":8' in outgoing.getvalue()


def test_clear_cache_preserves_unrelated_files(tmp_path: Path) -> None:
    from concurrency_guard.cache.file_cache import FileCache

    source = tmp_path / "source.py"
    source.write_text("pass", encoding="utf-8")
    cache = FileCache(tmp_path)
    cache.set(source, [])
    directory = tmp_path / "notes"
    directory.mkdir()
    nested = directory / "draft.txt"
    nested.write_text("keep", encoding="utf-8")
    assert cache.clear() == 1
    assert source.is_file()
    assert nested.read_text(encoding="utf-8") == "keep"

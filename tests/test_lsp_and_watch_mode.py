"""Tests for the LSP Language Server and File Watch mode.

Covers:
1. LSP framing & initialize handshake
2. Live in-memory didOpen/didChange diagnostics
3. QuickFix textDocument/codeAction with WorkspaceEdit
4. Clean document clears diagnostics
5. cguard watch --once execution
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from io import BytesIO
from pathlib import Path
from typing import Any

from concurrency_guard.lsp import (
    DocumentStore,
    create_test_server,
    encode_message,
    finding_to_diagnostic,
    read_message,
)
from concurrency_guard.scanner.ast_rules import ASTFinding
from concurrency_guard.watch import (
    watch_project,
)

# --- Vulnerable code fixture (CG-001: unlocked read-modify-write) ---

VULNERABLE_CODE = textwrap.dedent("""\
    from fastapi import Depends, FastAPI
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession

    app = FastAPI()

    @app.post("/wallet/withdraw")
    async def withdraw(db: AsyncSession = Depends(get_db)):
        stmt = select(Wallet).where(Wallet.user_id == 1)
        result = await db.execute(stmt)
        wallet = result.scalar_one_or_none()
        wallet.balance -= 50
        await db.commit()
        return {"balance": wallet.balance}
""")

FIXED_CODE = textwrap.dedent("""\
    from fastapi import Depends, FastAPI
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession

    app = FastAPI()

    @app.post("/wallet/withdraw")
    async def withdraw(db: AsyncSession = Depends(get_db)):
        stmt = select(Wallet).where(Wallet.user_id == 1).with_for_update()
        result = await db.execute(stmt)
        wallet = result.scalar_one_or_none()
        wallet.balance -= 50
        await db.commit()
        return {"balance": wallet.balance}
""")


# --- Helper to read all responses from server output ---

def _read_all_messages(writer: BytesIO) -> list[dict[str, Any]]:
    """Read all JSON-RPC messages from the writer BytesIO."""
    writer.seek(0)
    messages: list[dict[str, Any]] = []
    while True:
        msg = read_message(writer)
        if msg is None:
            break
        messages.append(msg)
    return messages


# --- Test 1: LSP Framing & initialize Handshake ---

class TestLSPFramingAndInitialize:
    """Test LSP JSON-RPC framing and initialize handshake."""

    def test_encode_message_has_content_length_header(self) -> None:
        """Verify encode_message produces valid Content-Length framing."""
        body = {"jsonrpc": "2.0", "id": 1, "method": "test"}
        encoded = encode_message(body)

        # Must start with Content-Length header
        assert encoded.startswith(b"Content-Length: ")
        # Must have \r\n\r\n separator
        assert b"\r\n\r\n" in encoded

        # Parse out Content-Length
        header_end = encoded.index(b"\r\n\r\n")
        header = encoded[:header_end].decode("ascii")
        content_length = int(header.split(":")[1].strip())

        # Verify content length matches actual JSON body
        json_body = encoded[header_end + 4:]
        assert len(json_body) == content_length

        # Verify JSON is valid
        parsed = json.loads(json_body)
        assert parsed["jsonrpc"] == "2.0"
        assert parsed["id"] == 1

    def test_read_message_roundtrip(self) -> None:
        """Verify read_message correctly decodes an encoded message."""
        original = {"jsonrpc": "2.0", "id": 42, "method": "initialize", "params": {}}
        buf = BytesIO(encode_message(original))
        decoded = read_message(buf)
        assert decoded is not None
        assert decoded["id"] == 42
        assert decoded["method"] == "initialize"

    def test_initialize_handshake(self) -> None:
        """Send initialize request and verify server capabilities."""
        server, _reader, writer = create_test_server()

        init_msg: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": os.getpid(),
                "rootUri": "file:///tmp/test",
                "capabilities": {},
            },
        }

        server.handle_message(init_msg)

        messages = _read_all_messages(writer)
        assert len(messages) == 1

        response = messages[0]
        assert response["id"] == 1
        assert "result" in response

        result = response["result"]
        caps = result["capabilities"]

        # Verify textDocumentSync
        assert caps["textDocumentSync"]["openClose"] is True
        assert caps["textDocumentSync"]["change"] == 1  # Full sync

        # Verify codeActionProvider
        assert caps["codeActionProvider"] is True

        # Verify serverInfo
        assert result["serverInfo"]["name"] == "ConcurrencyGuard"


# --- Test 2: Live In-Memory didOpen/didChange Diagnostics ---

class TestPublishDiagnostics:
    """Test real-time in-memory AST diagnostics."""

    def test_did_open_publishes_diagnostics(self) -> None:
        """Send didOpen with vulnerable code -> verify CG-001 diagnostic."""
        server, _reader, writer = create_test_server()

        # Initialize first
        server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": 1, "rootUri": "file:///tmp", "capabilities": {}},
        })

        # Clear writer for clean diagnostic capture
        writer.seek(0)
        writer.truncate()

        # Send didOpen
        server.handle_message({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///tmp/test.py",
                    "languageId": "python",
                    "version": 1,
                    "text": VULNERABLE_CODE,
                },
            },
        })

        messages = _read_all_messages(writer)
        # Should have a publishDiagnostics notification
        diag_msgs = [m for m in messages if m.get("method") == "textDocument/publishDiagnostics"]
        assert len(diag_msgs) >= 1

        diag_notification = diag_msgs[0]
        params = diag_notification["params"]
        assert params["uri"] == "file:///tmp/test.py"

        diagnostics = params["diagnostics"]
        assert len(diagnostics) >= 1

        # Find the CG-001 diagnostic
        cg001_diags = [d for d in diagnostics if d["code"] == "CG-001"]
        assert len(cg001_diags) >= 1

        diag = cg001_diags[0]
        assert diag["source"] == "ConcurrencyGuard"
        assert diag["severity"] == 1  # Error for HIGH confidence
        # 0-based line numbers
        assert diag["range"]["start"]["line"] >= 0

    def test_did_change_updates_diagnostics(self) -> None:
        """Send didChange with vulnerable code -> verify diagnostics update."""
        server, _reader, writer = create_test_server()

        server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": 1, "rootUri": "file:///tmp", "capabilities": {}},
        })

        # Open with safe code first
        server.handle_message({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///tmp/test.py",
                    "languageId": "python",
                    "version": 1,
                    "text": "print('hello')\n",
                },
            },
        })

        # Clear and send didChange with vulnerable code
        writer.seek(0)
        writer.truncate()

        server.handle_message({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": "file:///tmp/test.py", "version": 2},
                "contentChanges": [{"text": VULNERABLE_CODE}],
            },
        })

        messages = _read_all_messages(writer)
        diag_msgs = [m for m in messages if m.get("method") == "textDocument/publishDiagnostics"]
        assert len(diag_msgs) >= 1

        diagnostics = diag_msgs[0]["params"]["diagnostics"]
        codes = {d["code"] for d in diagnostics}
        assert "CG-001" in codes


# --- Test 3: LSP QuickFix textDocument/codeAction ---

class TestQuickFixCodeAction:
    """Test one-click IDE Quick-Fix CodeActions."""

    def test_code_action_returns_quickfix(self) -> None:
        """Request codeAction for CG-001 diagnostic range -> verify quickfix WorkspaceEdit."""
        server, _reader, writer = create_test_server()

        # Initialize
        server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": 1, "rootUri": "file:///tmp", "capabilities": {}},
        })

        # Open vulnerable file
        uri = "file:///tmp/test_fix.py"
        server.handle_message({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "languageId": "python",
                    "version": 1,
                    "text": VULNERABLE_CODE,
                },
            },
        })

        # Clear writer
        writer.seek(0)
        writer.truncate()

        # Request code actions at the vulnerable line
        server.handle_message({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/codeAction",
            "params": {
                "textDocument": {"uri": uri},
                "range": {
                    "start": {"line": 8, "character": 0},
                    "end": {"line": 13, "character": 0},
                },
                "context": {
                    "diagnostics": [
                        {
                            "range": {
                                "start": {"line": 8, "character": 0},
                                "end": {"line": 13, "character": 0},
                            },
                            "severity": 1,
                            "code": "CG-001",
                            "source": "ConcurrencyGuard",
                            "message": "Unlocked Read-Modify-Write",
                        },
                    ],
                },
            },
        })

        messages = _read_all_messages(writer)
        # Find the codeAction response
        response_msgs = [m for m in messages if m.get("id") == 2]
        assert len(response_msgs) == 1

        result = response_msgs[0]["result"]
        assert isinstance(result, list)
        assert len(result) >= 1

        action = result[0]
        assert action["kind"] == "quickfix"
        assert action["isPreferred"] is True
        assert "CG-001" in action["title"]
        assert "ConcurrencyGuard" in action["title"]

        # Verify WorkspaceEdit contains the fix
        edit = action["edit"]
        assert "changes" in edit
        assert uri in edit["changes"]

        text_edits = edit["changes"][uri]
        assert len(text_edits) >= 1

        new_text = text_edits[0]["newText"]
        assert "with_for_update()" in new_text


# --- Test 4: Clean Document Clears Diagnostics ---

class TestCleanDocumentClearsDiagnostics:
    """Test that updating to clean code clears all diagnostics."""

    def test_fixed_code_clears_diagnostics(self) -> None:
        """Send didChange with fixed code -> verify empty diagnostics array."""
        server, _reader, writer = create_test_server()

        # Initialize
        server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": 1, "rootUri": "file:///tmp", "capabilities": {}},
        })

        # Open with vulnerable code
        uri = "file:///tmp/test_clear.py"
        server.handle_message({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "languageId": "python",
                    "version": 1,
                    "text": VULNERABLE_CODE,
                },
            },
        })

        # Now send didChange with the FIXED code
        writer.seek(0)
        writer.truncate()

        server.handle_message({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": uri, "version": 2},
                "contentChanges": [{"text": FIXED_CODE}],
            },
        })

        messages = _read_all_messages(writer)
        diag_msgs = [m for m in messages if m.get("method") == "textDocument/publishDiagnostics"]
        assert len(diag_msgs) >= 1

        diagnostics = diag_msgs[0]["params"]["diagnostics"]
        # CG-001 should be gone since we added .with_for_update()
        cg001_diags = [d for d in diagnostics if d["code"] == "CG-001"]
        assert len(cg001_diags) == 0


# --- Test 5: cguard watch --once Execution ---

class TestWatchOnce:
    """Test cguard watch --once execution."""

    def test_watch_once_detects_findings(self, tmp_path: Path) -> None:
        """Run watch_project with once=True on vulnerable code."""
        test_file = tmp_path / "vuln.py"
        test_file.write_text(VULNERABLE_CODE, encoding="utf-8")

        output = BytesIO()
        # Use TextIOWrapper since watch_project writes to stderr-like stream
        import io

        text_out = io.TextIOWrapper(output, encoding="utf-8", write_through=True)

        results = watch_project(
            tmp_path,
            once=True,
            output_stream=text_out,
            colorize=False,
        )

        assert len(results) == 1
        result = results[0]
        assert result.cycle == 1
        assert result.scanned_files >= 1
        assert result.changed_files >= 1
        assert len(result.findings) >= 1

        # Should contain CG-001
        rule_ids = {f.rule_id for f in result.findings}
        assert "CG-001" in rule_ids

    def test_watch_once_clean_code_no_findings(self, tmp_path: Path) -> None:
        """Run watch --once on clean code -> verify no findings."""
        test_file = tmp_path / "clean.py"
        test_file.write_text("def hello() -> None:\n    print('hello')\n", encoding="utf-8")

        output = BytesIO()
        import io

        text_out = io.TextIOWrapper(output, encoding="utf-8", write_through=True)

        results = watch_project(
            tmp_path,
            once=True,
            output_stream=text_out,
            colorize=False,
        )

        assert len(results) == 1
        assert len(results[0].findings) == 0

    def test_watch_once_cli_execution(self, tmp_path: Path) -> None:
        """Run 'cguard watch --once' via subprocess."""
        test_file = tmp_path / "vuln_cli.py"
        test_file.write_text(VULNERABLE_CODE, encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-m", "concurrency_guard.cli", "watch", str(tmp_path), "--once"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        # Exit code 1 because findings exist
        assert result.returncode == 1
        # Should have output on stderr
        assert "CG-001" in result.stderr or "Cycle #1" in result.stderr


# --- Test 6: DocumentStore Thread Safety ---

class TestDocumentStore:
    """Test DocumentStore open/update/get/close operations."""

    def test_open_and_get(self) -> None:
        """Open a document and retrieve it."""
        store = DocumentStore()
        store.open("file:///test.py", "print('hello')", version=1)
        doc = store.get("file:///test.py")
        assert doc is not None
        assert doc.content == "print('hello')"
        assert doc.version == 1

    def test_update_content(self) -> None:
        """Update document content and verify."""
        store = DocumentStore()
        store.open("file:///test.py", "v1", version=1)
        store.update("file:///test.py", "v2", version=2)
        doc = store.get("file:///test.py")
        assert doc is not None
        assert doc.content == "v2"
        assert doc.version == 2

    def test_close_removes_document(self) -> None:
        """Close a document and verify it's removed."""
        store = DocumentStore()
        store.open("file:///test.py", "content")
        store.close("file:///test.py")
        assert store.get("file:///test.py") is None


# --- Test 7: Finding to Diagnostic Conversion ---

class TestFindingToDiagnostic:
    """Test ASTFinding -> Diagnostic conversion."""

    def test_high_confidence_becomes_error(self) -> None:
        """HIGH confidence findings map to severity 1 (Error)."""
        finding = ASTFinding(
            rule_id="CG-001",
            filename="test.py",
            lineno=10,
            function_name="withdraw",
            message="Unlocked RMW",
            suggested_fix_hint="Add .with_for_update()",
            confidence="HIGH",
        )
        diag = finding_to_diagnostic(finding)
        assert diag.severity == 1
        assert diag.code == "CG-001"
        assert diag.source == "ConcurrencyGuard"
        # 0-based line
        assert diag.range.start.line == 9

    def test_medium_confidence_becomes_warning(self) -> None:
        """MEDIUM confidence findings map to severity 2 (Warning)."""
        finding = ASTFinding(
            rule_id="CG-003",
            filename="test.py",
            lineno=5,
            function_name="fetch",
            message="N+1 query",
            suggested_fix_hint="Use joined load",
            confidence="MEDIUM",
        )
        diag = finding_to_diagnostic(finding)
        assert diag.severity == 2


# --- Test 8: LSP shutdown/exit Lifecycle ---

class TestLSPLifecycle:
    """Test LSP shutdown and exit lifecycle."""

    def test_shutdown_then_exit(self) -> None:
        """Verify shutdown sets flag and exit returns False."""
        server, _reader, _writer = create_test_server()

        # Initialize
        server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": 1, "rootUri": "file:///tmp", "capabilities": {}},
        })

        # Shutdown
        result = server.handle_message({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "shutdown",
        })
        assert result is True  # Should continue until exit

        # Exit
        result = server.handle_message({
            "jsonrpc": "2.0",
            "method": "exit",
        })
        assert result is False  # Should stop

    def test_unknown_method_returns_error(self) -> None:
        """Unknown request method should return MethodNotFound error."""
        server, _reader, writer = create_test_server()

        server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"processId": 1, "rootUri": "file:///tmp", "capabilities": {}},
        })

        writer.seek(0)
        writer.truncate()

        server.handle_message({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "textDocument/unknownMethod",
        })

        messages = _read_all_messages(writer)
        error_msgs = [m for m in messages if "error" in m]
        assert len(error_msgs) == 1
        assert error_msgs[0]["error"]["code"] == -32601

"""Zero-dependency Language Server Protocol (LSP 3.17) engine for ConcurrencyGuard.

Implements a JSON-RPC 2.0 server over stdin/stdout that provides:
- Real-time AST diagnostics via textDocument/publishDiagnostics
- One-click IDE Quick-Fix CodeActions via textDocument/codeAction
- Full document sync on open/change/save

Requires ONLY Python standard library modules (zero external LSP frameworks).
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from dataclasses import dataclass
from io import BytesIO
from typing import IO, Any, Optional, Union

from concurrency_guard import __version__
from concurrency_guard.patcher.cst_fixer import apply_all_fixes_with_report
from concurrency_guard.scanner.ast_rules import ASTFinding, scan_source_code

logger = logging.getLogger("cguard.lsp")

# --- LSP Data Structures ---


@dataclass(frozen=True)
class Position:
    """LSP 0-based line/character position."""

    line: int
    character: int


@dataclass(frozen=True)
class Range:
    """LSP range with start and end positions."""

    start: Position
    end: Position


@dataclass(frozen=True)
class Diagnostic:
    """LSP Diagnostic object."""

    range: Range
    severity: int
    code: str
    source: str
    message: str


@dataclass(frozen=True)
class TextEdit:
    """LSP TextEdit for workspace edits."""

    range: Range
    newText: str


@dataclass
class CodeAction:
    """LSP CodeAction for quick-fix suggestions."""

    title: str
    kind: str
    diagnostics: list[dict[str, Any]]
    isPreferred: bool
    edit: dict[str, Any]


# --- Rule Severity Mapping ---

_HIGH_CONFIDENCE_RULES: frozenset[str] = frozenset({"CG-001", "CG-004"})

_FIXABLE_RULES: frozenset[str] = frozenset({
    "CG-001", "CG-002", "CG-004", "CG-006", "CG-007",
    "CG-009", "CG-016", "CG-017",
})


def _severity_for_finding(finding: ASTFinding) -> int:
    """Map ASTFinding confidence to LSP DiagnosticSeverity.

    1 = Error, 2 = Warning, 3 = Information, 4 = Hint.
    """
    confidence = (finding.confidence or "HIGH").upper()
    if confidence == "HIGH" or finding.rule_id in _HIGH_CONFIDENCE_RULES:
        return 1
    if confidence == "MEDIUM":
        return 2
    return 2  # LOW -> Warning


def finding_to_diagnostic(finding: ASTFinding) -> Diagnostic:
    """Convert an ASTFinding to an LSP Diagnostic."""
    start_line = max(0, finding.lineno - 1)  # 1-based -> 0-based
    end_line = max(start_line, (finding.end_lineno or finding.lineno) - 1)
    col = finding.col_offset or 0

    message_parts = [finding.message]
    if finding.suggested_fix_hint:
        message_parts.append(f"Fix: {finding.suggested_fix_hint}")

    return Diagnostic(
        range=Range(
            start=Position(line=start_line, character=col),
            end=Position(line=end_line, character=0),
        ),
        severity=_severity_for_finding(finding),
        code=finding.rule_id,
        source="ConcurrencyGuard",
        message=" | ".join(message_parts),
    )


def diagnostic_to_dict(diag: Diagnostic) -> dict[str, Any]:
    """Serialize a Diagnostic to LSP-compliant JSON dict."""
    return {
        "range": {
            "start": {"line": diag.range.start.line, "character": diag.range.start.character},
            "end": {"line": diag.range.end.line, "character": diag.range.end.character},
        },
        "severity": diag.severity,
        "code": diag.code,
        "source": diag.source,
        "message": diag.message,
    }


# --- In-Memory Document Store ---


@dataclass
class DocumentState:
    """Tracks the latest content of an open text document."""

    uri: str
    content: str
    version: int = 0


class DocumentStore:
    """Thread-safe in-memory document buffer."""

    def __init__(self) -> None:
        self._documents: dict[str, DocumentState] = {}
        self._lock = threading.Lock()

    def open(self, uri: str, content: str, version: int = 0) -> DocumentState:
        """Register a newly opened document."""
        doc = DocumentState(uri=uri, content=content, version=version)
        with self._lock:
            self._documents[uri] = doc
        return doc

    def update(self, uri: str, content: str, version: int = 0) -> Optional[DocumentState]:
        """Update document content (full sync)."""
        with self._lock:
            doc = self._documents.get(uri)
            if doc is None:
                doc = DocumentState(uri=uri, content=content, version=version)
                self._documents[uri] = doc
            else:
                doc.content = content
                doc.version = version
        return doc

    def get(self, uri: str) -> Optional[DocumentState]:
        """Retrieve current document state."""
        with self._lock:
            return self._documents.get(uri)

    def close(self, uri: str) -> None:
        """Remove a closed document."""
        with self._lock:
            self._documents.pop(uri, None)


# --- Quick-Fix CodeAction Generation ---


def _uri_to_filepath(uri: str) -> str:
    """Convert a file:// URI to a local filesystem path."""
    if uri.startswith("file:///"):
        return uri[7:]
    if uri.startswith("file://"):
        return uri[7:]
    return uri


def generate_code_actions(
    uri: str,
    source_code: str,
    diagnostics: list[dict[str, Any]],
    request_range: dict[str, Any],
) -> list[dict[str, Any]]:
    """Generate QuickFix CodeActions for fixable diagnostics in the requested range.

    For each fixable diagnostic overlapping the cursor/selection range, runs
    the LibCST patcher in-memory and returns a WorkspaceEdit TextEdit.
    """
    actions: list[dict[str, Any]] = []

    req_start_line = request_range.get("start", {}).get("line", 0)
    req_end_line = request_range.get("end", {}).get("line", req_start_line)

    # Filter diagnostics to those in the requested range and fixable
    fixable_diags: list[dict[str, Any]] = []
    for diag in diagnostics:
        diag_code = diag.get("code", "")
        if diag_code not in _FIXABLE_RULES:
            continue
        diag_start = diag.get("range", {}).get("start", {}).get("line", -1)
        diag_end = diag.get("range", {}).get("end", {}).get("line", diag_start)
        # Check overlap between request range and diagnostic range
        if diag_end < req_start_line or diag_start > req_end_line:
            continue
        fixable_diags.append(diag)

    if not fixable_diags:
        return actions

    # Deduplicate by rule_id to avoid running the patcher multiple times for same rule
    seen_rules: set[str] = set()
    for diag in fixable_diags:
        rule_id = diag.get("code", "")
        if rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)

        try:
            result = apply_all_fixes_with_report(
                source_code,
                selected_rules={rule_id},
                dry_run=True,
            )
        except Exception:  # noqa: BLE001, S112
            continue

        if not result.modified:
            continue

        # Create a full-document TextEdit replacing the entire source
        lines = source_code.splitlines(keepends=True)
        end_line = max(0, len(lines) - 1)
        last_line = lines[-1] if lines else ""
        end_char = len(last_line.rstrip("\r\n")) if last_line else 0

        text_edit: dict[str, Any] = {
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": end_line, "character": end_char},
            },
            "newText": result.code,
        }

        action: dict[str, Any] = {
            "title": f"ConcurrencyGuard: Auto-fix {rule_id} with LibCST",
            "kind": "quickfix",
            "diagnostics": [diag],
            "isPreferred": True,
            "edit": {
                "changes": {
                    uri: [text_edit],
                },
            },
        }
        actions.append(action)

    return actions


# --- JSON-RPC 2.0 Framing ---


def encode_message(body: dict[str, Any]) -> bytes:
    """Encode a JSON-RPC message with Content-Length header."""
    content = json.dumps(body, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(content)}\r\n\r\n".encode("ascii")
    return header + content


def decode_header(stream: IO[bytes]) -> Optional[int]:
    """Read LSP headers from byte stream, return Content-Length or None on EOF."""
    content_length: Optional[int] = None
    while True:
        line = stream.readline()
        if not line:
            return None  # EOF
        line_str = line.decode("ascii", errors="replace").strip()
        if not line_str:
            break  # Empty line = end of headers
        if line_str.lower().startswith("content-length:"):
            try:
                content_length = int(line_str.split(":", 1)[1].strip())
            except (ValueError, IndexError):
                pass
    return content_length


def read_message(stream: IO[bytes]) -> Optional[dict[str, Any]]:
    """Read a single JSON-RPC message from byte stream."""
    content_length = decode_header(stream)
    if content_length is None:
        return None
    body_bytes = stream.read(content_length)
    if len(body_bytes) < content_length:
        return None
    return json.loads(body_bytes.decode("utf-8"))  # type: ignore[no-any-return]


# --- LSP Server Engine ---


class LanguageServer:
    """Zero-dependency LSP 3.17 server for ConcurrencyGuard."""

    def __init__(
        self,
        reader: IO[bytes],
        writer: IO[bytes],
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._documents = DocumentStore()
        self._shutdown_requested = False
        self._initialized = False
        self._write_lock = threading.Lock()
        # Cache diagnostics per URI for code action requests
        self._cached_diagnostics: dict[str, list[dict[str, Any]]] = {}

    def _send(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC message to the client."""
        data = encode_message(message)
        with self._write_lock:
            self._writer.write(data)
            self._writer.flush()

    def _send_response(self, request_id: Union[int, str, None], result: Any) -> None:
        """Send a JSON-RPC response."""
        self._send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        })

    def _send_error(
        self,
        request_id: Union[int, str, None],
        code: int,
        message: str,
    ) -> None:
        """Send a JSON-RPC error response."""
        self._send({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        })

    def _send_notification(self, method: str, params: Any) -> None:
        """Send a JSON-RPC notification (no id)."""
        self._send({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        })

    def _publish_diagnostics(self, uri: str, source_code: str) -> list[dict[str, Any]]:
        """Run AST scanner on source and publish diagnostics."""
        filepath = _uri_to_filepath(uri)
        try:
            findings = scan_source_code(source_code, filename=filepath)
        except Exception:  # noqa: BLE001
            findings = []

        diagnostics = [diagnostic_to_dict(finding_to_diagnostic(f)) for f in findings]

        # Cache diagnostics for code action requests
        self._cached_diagnostics[uri] = diagnostics

        self._send_notification(
            "textDocument/publishDiagnostics",
            {
                "uri": uri,
                "diagnostics": diagnostics,
            },
        )
        return diagnostics

    # --- Request Handlers ---

    def _handle_initialize(
        self,
        request_id: Union[int, str, None],
        params: dict[str, Any],
    ) -> None:
        """Handle initialize request."""
        capabilities: dict[str, Any] = {
            "textDocumentSync": {
                "openClose": True,
                "change": 1,  # TextDocumentSyncKind.Full
                "save": {"includeText": True},
            },
            "codeActionProvider": True,
        }

        self._send_response(request_id, {
            "capabilities": capabilities,
            "serverInfo": {
                "name": "ConcurrencyGuard",
                "version": __version__,
            },
        })

    def _handle_initialized(self, params: dict[str, Any]) -> None:
        """Handle initialized notification."""
        self._initialized = True

    def _handle_shutdown(self, request_id: Union[int, str, None]) -> None:
        """Handle shutdown request."""
        self._shutdown_requested = True
        self._send_response(request_id, None)

    def _handle_did_open(self, params: dict[str, Any]) -> None:
        """Handle textDocument/didOpen notification."""
        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        text = td.get("text", "")
        version = td.get("version", 0)

        self._documents.open(uri, text, version)
        self._publish_diagnostics(uri, text)

    def _handle_did_change(self, params: dict[str, Any]) -> None:
        """Handle textDocument/didChange notification (full sync)."""
        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        version = td.get("version", 0)

        changes = params.get("contentChanges", [])
        if changes:
            # Full document sync: last change contains the full text
            text = changes[-1].get("text", "")
            self._documents.update(uri, text, version)
            self._publish_diagnostics(uri, text)

    def _handle_did_save(self, params: dict[str, Any]) -> None:
        """Handle textDocument/didSave notification."""
        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        text = params.get("text")

        if text is not None:
            self._documents.update(uri, text)
            self._publish_diagnostics(uri, text)
        else:
            doc = self._documents.get(uri)
            if doc is not None:
                self._publish_diagnostics(uri, doc.content)

    def _handle_did_close(self, params: dict[str, Any]) -> None:
        """Handle textDocument/didClose notification."""
        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        self._documents.close(uri)
        self._cached_diagnostics.pop(uri, None)
        # Clear diagnostics in the editor
        self._send_notification(
            "textDocument/publishDiagnostics",
            {"uri": uri, "diagnostics": []},
        )

    def _handle_code_action(
        self,
        request_id: Union[int, str, None],
        params: dict[str, Any],
    ) -> None:
        """Handle textDocument/codeAction request."""
        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        request_range = params.get("range", {})
        context = params.get("context", {})
        client_diagnostics = context.get("diagnostics", [])

        doc = self._documents.get(uri)
        if doc is None:
            self._send_response(request_id, [])
            return

        # Use cached diagnostics if client didn't send any
        diagnostics = client_diagnostics if client_diagnostics else self._cached_diagnostics.get(uri, [])

        actions = generate_code_actions(uri, doc.content, diagnostics, request_range)
        self._send_response(request_id, actions)

    # --- Main Loop ---

    def _dispatch(self, message: dict[str, Any]) -> bool:
        """Dispatch a JSON-RPC message. Returns False to exit."""
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params", {})

        if method == "initialize":
            self._handle_initialize(request_id, params)
        elif method == "initialized":
            self._handle_initialized(params)
        elif method == "shutdown":
            self._handle_shutdown(request_id)
        elif method == "exit":
            return False
        elif method == "textDocument/didOpen":
            self._handle_did_open(params)
        elif method == "textDocument/didChange":
            self._handle_did_change(params)
        elif method == "textDocument/didSave":
            self._handle_did_save(params)
        elif method == "textDocument/didClose":
            self._handle_did_close(params)
        elif method == "textDocument/codeAction":
            self._handle_code_action(request_id, params)
        elif request_id is not None:
            # Unknown request method: respond with MethodNotFound
            self._send_error(request_id, -32601, f"Method not found: {method}")

        return True

    def run(self) -> int:
        """Run the server main loop, returning exit code."""
        while True:
            message = read_message(self._reader)
            if message is None:
                break  # EOF
            should_continue = self._dispatch(message)
            if not should_continue:
                return 0 if self._shutdown_requested else 1
        return 0 if self._shutdown_requested else 1

    def handle_message(self, message: dict[str, Any]) -> bool:
        """Handle a single message. Returns True to continue, False to exit.

        Useful for testing without running the full stdio loop.
        """
        return self._dispatch(message)


def run_lsp_server(
    reader: Optional[IO[bytes]] = None,
    writer: Optional[IO[bytes]] = None,
) -> int:
    """Entry point: run the LSP server over stdin/stdout."""
    effective_reader = reader or sys.stdin.buffer
    effective_writer = writer or sys.stdout.buffer
    server = LanguageServer(effective_reader, effective_writer)
    return server.run()


# --- Convenience for testing ---


def create_test_server() -> tuple[LanguageServer, BytesIO, BytesIO]:
    """Create a LanguageServer with in-memory byte streams for testing."""
    reader = BytesIO()
    writer = BytesIO()
    server = LanguageServer(reader, writer)
    return server, reader, writer


def inject_message(reader: BytesIO, message: dict[str, Any]) -> None:
    """Write a framed JSON-RPC message into a BytesIO reader for testing."""
    data = encode_message(message)
    pos = reader.tell()
    reader.seek(0, 2)  # Seek to end
    reader.write(data)
    reader.seek(pos)  # Restore position


__all__ = [
    "CodeAction",
    "Diagnostic",
    "DocumentState",
    "DocumentStore",
    "LanguageServer",
    "Position",
    "Range",
    "TextEdit",
    "create_test_server",
    "decode_header",
    "diagnostic_to_dict",
    "encode_message",
    "finding_to_diagnostic",
    "generate_code_actions",
    "inject_message",
    "read_message",
    "run_lsp_server",
]

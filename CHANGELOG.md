# Changelog

## 3.10.0

- Replace source fixes, reports, baselines, and file-cache entries atomically.
- Skip symlinks during file discovery and check project import and file-cache path boundaries.
- Recover from malformed Python input and bound control-flow graph depth and block count.
- Recover from malformed LSP JSON-RPC frames.
- Validate SARIF rule identifiers, severity levels, and CWE metadata before serialization.

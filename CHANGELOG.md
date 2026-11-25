# Changelog

## 4.0.0

- Detect shared async sessions, recursive async lock acquisition, and swallowed cancellation.
- Add a LibCST cancellation fix and SARIF and HTML reporting for the new rules.
- Add an opt-in SDK for trusted local Python rule plugins.
- Add Git diff scanning of committed Python changes and their transitive importers.

## 3.10.0

- Replace source fixes, reports, baselines, and file-cache entries atomically.
- Skip symlinks during file discovery and check project import and file-cache path boundaries.
- Recover from malformed Python input and bound control-flow graph depth and block count.
- Recover from malformed LSP JSON-RPC frames.
- Validate SARIF rule identifiers, severity levels, and CWE metadata before serialization.

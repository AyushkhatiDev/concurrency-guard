"""Parse-Once IR & Parallel Multi-Core Scanner Engine.

Implements lightweight ParsedModule IR so every .py file is read and parsed via
ast.parse() exactly once per scan, sharing the parsed AST across
ProjectSymbolGraph, taint tracking, and rule visitors.
"""

from __future__ import annotations

import ast
import concurrent.futures
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from concurrency_guard.scanner.ast_rules import (
    ASTFinding,
    discover_python_files,
    scan_file,
    sort_findings,
)
from concurrency_guard.scanner.call_graph import build_call_graph
from concurrency_guard.scanner.suppression import SuppressionFilter
from concurrency_guard.scanner.taint_tracker import find_tainted_shared_state_mutations


@dataclass(frozen=True)
class ParsedModule:
    """Lightweight Intermediate Representation of a parsed Python source file."""

    path: Path
    source: str
    tree: ast.Module
    sha256: str

    @classmethod
    def from_file(cls, path: Path) -> Optional[ParsedModule]:
        """Read and parse a file from disk into a ParsedModule, or return None on error."""
        try:
            resolved = path.resolve()
            source = resolved.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=str(resolved))
            digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
            return cls(path=resolved, source=source, tree=tree, sha256=digest)
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
            return None

    @classmethod
    def from_source(cls, source: str, path: Union[Path, str] = "<memory>") -> ParsedModule:
        """Parse source code string into a ParsedModule."""
        p = Path(path).resolve() if isinstance(path, (Path, str)) and path != "<memory>" else Path("<memory>")
        tree = ast.parse(source, filename=str(path))
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        return cls(path=p, source=source, tree=tree, sha256=digest)


def parse_module(path: Path) -> Optional[ParsedModule]:
    """Parse a single file into a ParsedModule."""
    return ParsedModule.from_file(path)


def parse_modules_parallel(
    file_paths: list[Path],
    max_workers: Optional[int] = None,
) -> dict[Path, ParsedModule]:
    """Parse a list of Python files into ParsedModule objects.

    Uses ThreadPoolExecutor when file_paths > 20 or when max_workers > 1,
    reusing ast.parse() across all consumers.
    """
    effective_workers = max_workers if (max_workers is not None and max_workers > 0) else (os.cpu_count() or 4)
    results: dict[Path, ParsedModule] = {}

    if len(file_paths) > 20 and effective_workers > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_workers) as executor:
            futures = {executor.submit(ParsedModule.from_file, p): p for p in file_paths}
            for future in concurrent.futures.as_completed(futures):
                pm = future.result()
                if pm is not None:
                    results[pm.path] = pm
    else:
        for p in file_paths:
            pm = ParsedModule.from_file(p)
            if pm is not None:
                results[pm.path] = pm

    return results


def scan_project_parallel(
    file_paths: list[Path],
    roots: Optional[list[Path]] = None,
    custom_rules: Optional[list[dict[str, Any]]] = None,
    cache_manager: Optional[Any] = None,
    suppression_filter: Optional[SuppressionFilter] = None,
    workers: Optional[int] = None,
    jobs: Optional[int] = None,
    config: Optional[Any] = None,
    cross_file: bool = True,
    parsed_modules: Optional[dict[Path, ParsedModule]] = None,
) -> list[ASTFinding]:
    """Scan files using parse-once IR and multi-core parallel execution.

    Auto-enables parallel processing when scanning > 20 files. Always guarantees
    deterministic output ordering sorted by (file_path, line, rule_id).
    """
    from concurrency_guard.project_graph import ProjectSymbolGraph

    active_filter = suppression_filter or SuppressionFilter()

    # Determine worker count
    num_jobs = jobs if jobs is not None else workers
    if num_jobs is not None:
        effective_jobs = max(1, num_jobs)
    elif len(file_paths) > 20:
        effective_jobs = os.cpu_count() or 4
    else:
        effective_jobs = 1

    # Step 1: Parse-Once IR
    if parsed_modules is None:
        modules_map = parse_modules_parallel(
            file_paths,
            max_workers=max(1, effective_jobs),
        )
    else:
        modules_map = parsed_modules

    # Step 2: Build Cross-File Project Symbol Graph with pre-parsed ASTs
    effective_cross_file = cross_file if cross_file is not None else getattr(config, "cross_file", True)
    project_graph: Optional[ProjectSymbolGraph] = None
    if effective_cross_file and file_paths:
        custom_locks = getattr(config, "custom_lock_names", None)
        project_graph = ProjectSymbolGraph.build(
            file_paths,
            roots=roots,
            custom_lock_names=custom_locks,
            parsed_modules=modules_map,
        )

    findings: list[ASTFinding] = []
    uncached_files: list[Path] = []

    # Step 3: Check cache
    if cache_manager is not None:
        for file_path in file_paths:
            dep_digest = project_graph.get_dependency_digest(file_path) if project_graph is not None else None
            cached: Optional[list[ASTFinding]] = None
            if hasattr(cache_manager, "get"):
                try:
                    cached = cache_manager.get(file_path, dependency_digest=dep_digest)
                except TypeError:
                    cached = cache_manager.get(file_path)
            elif hasattr(cache_manager, "get_cached_findings"):
                try:
                    raw_cached = cache_manager.get_cached_findings(file_path, dependency_digest=dep_digest)
                except TypeError:
                    raw_cached = cache_manager.get_cached_findings(file_path)
                if raw_cached is not None:
                    from concurrency_guard.cache.manager import dict_to_finding

                    cached = [dict_to_finding(d) for d in raw_cached]

            if cached is not None:
                findings.extend(active_filter.filter_findings(cached, file_path=file_path))
            else:
                uncached_files.append(file_path)
    else:
        uncached_files = list(file_paths)

    # Step 4: Scan uncached files (parallel when effective_jobs > 1 and files > 1)
    def _scan_one(fp: Path) -> list[ASTFinding]:
        resolved = fp.resolve()
        pm = modules_map.get(resolved) or modules_map.get(fp)
        return scan_file(
            fp,
            custom_rules=custom_rules,
            cache_manager=cache_manager,
            suppression_filter=active_filter,
            config=config,
            project_graph=project_graph,
            parsed_module=pm,
        )

    if uncached_files:
        if effective_jobs > 1 and len(uncached_files) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=effective_jobs) as executor:
                futures_map = {executor.submit(_scan_one, fp): fp for fp in uncached_files}
                for future in concurrent.futures.as_completed(futures_map):
                    file_findings = future.result()
                    findings.extend(file_findings)
        else:
            for fp in uncached_files:
                findings.extend(_scan_one(fp))

    if project_graph is not None:
        from concurrency_guard.deadlock_graph import project_deadlocks

        for cycle in project_deadlocks(((p, m.tree) for p, m in modules_map.items()), project_graph):
            findings.extend(active_filter.filter_findings([cycle], file_path=Path(cycle.filename)))

    # Step 5: Taint tracking & inter-procedural shared state hazards
    graph = build_call_graph(file_paths, roots=roots)
    taint_findings = find_tainted_shared_state_mutations(file_paths, graph)
    for finding in taint_findings:
        if not active_filter.should_suppress("CG-015", Path(finding.filename), finding.lineno):
            findings.append(
                ASTFinding(
                    rule_id="CG-015",
                    filename=finding.filename,
                    lineno=finding.lineno,
                    function_name=finding.function_name,
                    message=(
                        "Tainted Shared State Mutation: a local variable referencing shared state is "
                        "mutated without concurrency controls."
                    ),
                    suggested_fix_hint=(
                        "Protect the complete shared-state access with the appropriate lock or atomic "
                        "operation before mutating the local reference."
                    ),
                )
            )
        else:
            active_filter.suppressed_count += 1

    reported: set[tuple[str, str]] = set()
    for mutation in graph.shared_mutations:
        mutated = graph.functions[mutation]
        for caller_name in graph.callers_of(mutation):
            caller = graph.functions[caller_name]
            if caller.filename == mutated.filename:
                continue
            key = (caller_name, mutation)
            if key in reported:
                continue
            reported.add(key)
            if not active_filter.should_suppress("CG-014", Path(caller.filename), caller.lineno):
                findings.append(
                    ASTFinding(
                        rule_id="CG-014",
                        filename=caller.filename,
                        lineno=caller.lineno,
                        function_name=caller.name,
                        message=(
                            f"Inter-procedural shared-state race: call chain reaches '{mutation}', "
                            "which mutates module shared state."
                        ),
                        suggested_fix_hint=(
                            "Propagate a lock or synchronization boundary through the call chain, "
                            "or make the shared-state operation atomic in the callee."
                        ),
                    )
                )
            else:
                active_filter.suppressed_count += 1

    if config is not None and hasattr(config, "is_rule_enabled"):
        findings = [f for f in findings if config.is_rule_enabled(f.rule_id, file_path=f.filename)]

    # Step 6: Deterministic output ordering
    return sort_findings(findings)


def scan_directory_parallel(
    dir_path: Path,
    custom_rules: Optional[list[dict[str, Any]]] = None,
    cache_manager: Optional[Any] = None,
    suppression_filter: Optional[SuppressionFilter] = None,
    workers: Optional[int] = None,
    jobs: Optional[int] = None,
    config: Optional[Any] = None,
    cross_file: bool = True,
) -> list[ASTFinding]:
    """Scan a directory using parse-once IR and parallel worker execution."""
    py_files = discover_python_files(dir_path, config=config)
    return scan_project_parallel(
        py_files,
        roots=[dir_path],
        custom_rules=custom_rules,
        cache_manager=cache_manager,
        suppression_filter=suppression_filter,
        workers=workers,
        jobs=jobs,
        config=config,
        cross_file=cross_file,
    )

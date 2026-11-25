"""Cross-File Project Import Graph & Multi-Module Service-Layer Taint Propagation.

Resolves Python import statements across a workspace project so FunctionSummary
taint sources, lock sanitizers, and parameter mutations propagate across
repositories, services, and routers without executing or importing user code.
"""

from __future__ import annotations

import ast
import hashlib
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from concurrency_guard.scanner.call_graph import (
    FunctionSummary,
    analyze_module_functions,
)

logger = logging.getLogger(__name__)


def _dotted_name(node: ast.AST) -> str:
    """Return stable dotted expression name."""
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def resolve_module_path(
    current_file: Path,
    module_name: Optional[str],
    level: int = 0,
    roots: Optional[list[Path]] = None,
    known_files: Optional[set[Path]] = None,
) -> Optional[Path]:
    """Resolve a dotted module path or relative import to an exact workspace file path.

    Handles:
    - Relative imports (level > 0): from .helpers import x, from ..repositories.wallet import y
    - Absolute workspace imports (level == 0): from app.repositories.wallet import z
    - Workspace root / src / subpackage layouts
    - Both .py files and package directories with __init__.py
    """
    resolved_current = current_file.resolve()
    current_dir = resolved_current.parent

    # Candidate search roots
    search_roots: list[Path] = []
    if roots:
        for r in roots:
            rr = r.resolve()
            if rr not in search_roots:
                search_roots.append(rr)
            src_dir = rr / "src"
            if src_dir.is_dir() and src_dir not in search_roots:
                search_roots.append(src_dir)

    # Inferred common roots from current_dir
    p = current_dir
    while p != p.parent:
        if (p / "__init__.py").exists():
            p = p.parent
        else:
            if p not in search_roots:
                search_roots.append(p)
            break

    cwd = Path.cwd().resolve()
    if cwd not in search_roots:
        search_roots.append(cwd)

    # Known files indexed by canonical resolved path and relative parts
    canonical_known: set[Path] = {f.resolve() for f in (known_files or set())}

    def _match_candidate(cand: Path) -> Optional[Path]:
        """Check if candidate path corresponds to a valid Python file."""
        # 1. Direct .py file
        py_cand = cand.with_suffix(".py")
        if py_cand in canonical_known or py_cand.is_file():
            return py_cand
        # 2. Package __init__.py
        init_cand = cand / "__init__.py"
        if init_cand in canonical_known or init_cand.is_file():
            return init_cand
        # 3. Direct path if already .py
        if (cand in canonical_known or cand.is_file()) and cand.suffix == ".py":
            return cand
        return None

    # Case 1: Relative import (level > 0)
    if level > 0:
        base_dir = current_dir
        # level 1 = current_dir, level 2 = current_dir.parent, etc.
        for _ in range(level - 1):
            base_dir = base_dir.parent

        if module_name:
            parts = module_name.split(".")
            candidate = base_dir.joinpath(*parts)
        else:
            candidate = base_dir

        matched = _match_candidate(candidate)
        if matched is not None:
            return matched

    # Case 2: Absolute import (level == 0)
    if module_name:
        parts = module_name.split(".")

        # Try from current directory first (local peer imports)
        matched = _match_candidate(current_dir.joinpath(*parts))
        if matched is not None:
            return matched

        # Try against each search root
        for root in search_roots:
            candidate = root.joinpath(*parts)
            matched = _match_candidate(candidate)
            if matched is not None:
                return matched

        # Suffix matching fallback against known files
        parts_tuple = tuple(parts[:-1]) + (f"{parts[-1]}.py",)
        for kf in canonical_known:
            if len(kf.parts) >= len(parts_tuple) and kf.parts[-len(parts_tuple):] == parts_tuple:
                return kf

        single_suffix = (f"{parts[-1]}.py",)
        for kf in canonical_known:
            if len(kf.parts) >= 1 and kf.parts[-1:] == single_suffix and len(parts) > 1 and parts[-2] in kf.parts:
                return kf

    return None


@dataclass
class ProjectSymbolGraph:
    """Project-wide symbol table tracking cross-file functions, imports, and taint flow."""

    roots: list[Path] = field(default_factory=list)
    file_summaries: dict[Path, dict[str, FunctionSummary]] = field(default_factory=dict)
    imports_by_file: dict[Path, dict[str, tuple[Path, str]]] = field(default_factory=lambda: defaultdict(dict))
    file_dependency_hashes: dict[Path, str] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        file_paths: list[Path],
        roots: Optional[list[Path]] = None,
        custom_lock_names: Optional[Union[list[str], set[str]]] = None,
        parsed_modules: Optional[dict[Path, Any]] = None,
    ) -> ProjectSymbolGraph:
        """Construct the ProjectSymbolGraph in two deterministic passes."""
        effective_roots: list[Path] = []
        if roots:
            effective_roots = [r.resolve() for r in roots]
        elif file_paths:
            common = Path(os.path.commonpath([str(f.resolve().parent) for f in file_paths]))
            effective_roots = [common]
        else:
            effective_roots = [Path.cwd().resolve()]

        graph = cls(roots=effective_roots)
        known_files = {f.resolve() for f in file_paths}

        parsed_mods: dict[Path, tuple[ast.Module, str]] = {}

        # --- PASS 1: Parse and Index Local Function Summaries ---
        for fpath in file_paths:
            resolved_path = fpath.resolve()
            pm = None
            if parsed_modules:
                pm = parsed_modules.get(resolved_path) or parsed_modules.get(fpath)

            if pm is not None:
                if hasattr(pm, "tree") and hasattr(pm, "source"):
                    tree, code = pm.tree, pm.source
                elif isinstance(pm, tuple) and len(pm) == 2:
                    tree, code = pm
                else:
                    try:
                        code = resolved_path.read_text(encoding="utf-8-sig")
                        tree = ast.parse(code, filename=str(resolved_path))
                    except (OSError, UnicodeDecodeError, RecursionError, SyntaxError):
                        continue
            else:
                try:
                    code = resolved_path.read_text(encoding="utf-8-sig")
                    tree = ast.parse(code, filename=str(resolved_path))
                except (OSError, UnicodeDecodeError, RecursionError, SyntaxError):
                    continue

            parsed_mods[resolved_path] = (tree, code)

            # Analyze local function summaries
            summaries = analyze_module_functions(tree, custom_lock_names=custom_lock_names)

            # Also index class methods with ClassName.method_name prefix
            for item in tree.body:
                if isinstance(item, ast.ClassDef):
                    for method in item.body:
                        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            cls_qualified = f"{item.name}.{method.name}"
                            if method.name in summaries and cls_qualified not in summaries:
                                summaries[cls_qualified] = summaries[method.name]

            graph.file_summaries[resolved_path] = summaries

        # --- PASS 2: Import & Cross-File Call Resolution ---
        for resolved_path, (tree, _) in parsed_mods.items():
            imports: dict[str, tuple[Path, str]] = {}

            for stmt in tree.body:
                if isinstance(stmt, ast.Import):
                    for alias in stmt.names:
                        target = resolve_module_path(
                            resolved_path,
                            alias.name,
                            level=0,
                            roots=effective_roots,
                            known_files=known_files,
                        )
                        if target is not None:
                            local_name = alias.asname or alias.name.split(".")[0]
                            imports[local_name] = (target, "*")
                            if alias.asname:
                                imports[alias.asname] = (target, "*")
                            imports[alias.name] = (target, "*")

                elif isinstance(stmt, ast.ImportFrom):
                    mod_name = stmt.module
                    lvl = stmt.level or 0
                    target_file = resolve_module_path(
                        resolved_path,
                        mod_name,
                        level=lvl,
                        roots=effective_roots,
                        known_files=known_files,
                    )

                    for alias in stmt.names:
                        local_name = alias.asname or alias.name
                        # Check if the imported symbol is itself a submodule
                        combined_mod = f"{mod_name}.{alias.name}" if mod_name else alias.name
                        sub_target = resolve_module_path(
                            resolved_path,
                            combined_mod,
                            level=lvl,
                            roots=effective_roots,
                            known_files=known_files,
                        )

                        if sub_target is not None and sub_target != target_file:
                            imports[local_name] = (sub_target, "*")
                        elif target_file is not None:
                            imports[local_name] = (target_file, alias.name)

            graph.imports_by_file[resolved_path] = imports

        # --- PASS 3: Fixed-Point Cross-File Taint & Summary Propagation (max 3 iterations) ---
        for _ in range(3):
            changed = False
            for source_path, summaries in graph.file_summaries.items():
                if source_path not in parsed_mods:
                    continue
                tree, _ = parsed_mods[source_path]

                for func_node in (n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
                    summary = summaries.get(func_node.name)
                    if summary is None:
                        continue

                    param_to_idx = {arg.arg: idx for idx, arg in enumerate(func_node.args.args)}

                    # Inspect calls within func_node
                    for call in (n for n in ast.walk(func_node) if isinstance(n, ast.Call)):
                        res = graph.resolve_call(source_path, call)
                        if res is None:
                            continue
                        callee_sum, _, _ = res

                        # Propagate commit delegation
                        if callee_sum.performs_commit and not summary.performs_commit:
                            summary.performs_commit = True
                            changed = True

                        # Propagate lock context
                        if callee_sum.acquires_lock_context and not summary.acquires_lock_context:
                            summary.acquires_lock_context = True
                            changed = True

                        # Propagate parameter mutations across functions
                        for arg_idx, arg in enumerate(call.args):
                            if (
                                isinstance(arg, ast.Name)
                                and arg.id in param_to_idx
                                and arg_idx in callee_sum.mutated_param_indices
                            ):
                                p_idx = param_to_idx[arg.id]
                                if p_idx not in summary.mutated_param_indices:
                                    summary.mutated_param_indices.add(p_idx)
                                    summary.mutated_param_names.add(arg.id)
                                    changed = True

                        for kw in call.keywords:
                            if (
                                kw.arg
                                and isinstance(kw.value, ast.Name)
                                and kw.value.id in param_to_idx
                                and kw.arg in callee_sum.mutated_param_names
                            ):
                                p_idx = param_to_idx[kw.value.id]
                                if p_idx not in summary.mutated_param_indices:
                                    summary.mutated_param_indices.add(p_idx)
                                    summary.mutated_param_names.add(kw.value.id)
                                    changed = True

                    # Propagate returned entity taint from helper returns
                    for ret in (n for n in ast.walk(func_node) if isinstance(n, ast.Return)):
                        if ret.value is not None:
                            val = ret.value.value if isinstance(ret.value, ast.Await) else ret.value
                            if isinstance(val, ast.Call):
                                res = graph.resolve_call(source_path, val)
                                if res is not None:
                                    callee_sum, _, _ = res
                                    if callee_sum.returns_locked_entity and not summary.returns_locked_entity:
                                        summary.returns_locked_entity = True
                                        changed = True
                                    if callee_sum.returns_unlocked_entity and not summary.returns_unlocked_entity:
                                        summary.returns_unlocked_entity = True
                                        changed = True

            if not changed:
                break

        # Compute dependency digest for each file
        for fpath in file_paths:
            resolved_path = fpath.resolve()
            graph.file_dependency_hashes[resolved_path] = graph._compute_dependency_digest(resolved_path)

        return graph

    def resolve_call(
        self,
        source_file: Union[Path, str],
        call_or_func: ast.AST,
    ) -> Optional[tuple[FunctionSummary, Path, str]]:
        """Resolve a function or method call to its target FunctionSummary across files.

        Returns (summary, target_file_path, display_name) or None.
        """
        source_path = Path(source_file).resolve()
        func_expr = call_or_func.func if isinstance(call_or_func, ast.Call) else call_or_func

        imports = self.imports_by_file.get(source_path, {})

        # Case 1: Direct function call `get_wallet(...)`
        if isinstance(func_expr, ast.Name):
            name = func_expr.id
            if name in imports:
                target_file, target_symbol = imports[name]
                symbol = name if target_symbol == "*" else target_symbol
                summaries = self.file_summaries.get(target_file, {})
                if symbol in summaries:
                    return summaries[symbol], target_file, symbol
            # Check local file summaries
            local_summaries = self.file_summaries.get(source_path, {})
            if name in local_summaries:
                return local_summaries[name], source_path, name

        # Case 2: Attribute call `wallet_repo.get_wallet(...)` or `BillingService.debit(...)`
        elif isinstance(func_expr, ast.Attribute):
            attr_name = func_expr.attr
            prefix = _dotted_name(func_expr.value)

            # Check if prefix is directly imported: e.g. import wallet as wallet_repo
            if prefix in imports:
                target_file, target_symbol = imports[prefix]
                summaries = self.file_summaries.get(target_file, {})
                # Try direct symbol name
                if attr_name in summaries:
                    return summaries[attr_name], target_file, f"{prefix}.{attr_name}"
                # Try class-qualified method name: ClassName.method_name
                if target_symbol != "*":
                    cls_method = f"{target_symbol}.{attr_name}"
                    if cls_method in summaries:
                        return summaries[cls_method], target_file, f"{prefix}.{attr_name}"

            # Check if full dotted name is in imports
            full_dotted = f"{prefix}.{attr_name}"
            if full_dotted in imports:
                target_file, target_symbol = imports[full_dotted]
                summaries = self.file_summaries.get(target_file, {})
                if target_symbol in summaries:
                    return summaries[target_symbol], target_file, full_dotted

            # Check first component of prefix (e.g. `services.billing.debit` -> `services`)
            first_component = prefix.split(".")[0]
            if first_component in imports:
                target_file, _ = imports[first_component]
                summaries = self.file_summaries.get(target_file, {})
                if attr_name in summaries:
                    return summaries[attr_name], target_file, f"{prefix}.{attr_name}"

        return None

    def get_imported_files(self, file_path: Union[Path, str]) -> set[Path]:
        """Return the set of local project files imported by file_path."""
        p = Path(file_path).resolve()
        imports = self.imports_by_file.get(p, {})
        return {target_file for target_file, _ in imports.values() if target_file != p}

    def _compute_dependency_digest(self, file_path: Path) -> str:
        """Compute a SHA-256 digest of all directly and transitively imported local modules."""
        visited: set[Path] = set()
        queue = [file_path]

        while queue:
            curr = queue.pop()
            if curr in visited:
                continue
            visited.add(curr)
            for imported in self.get_imported_files(curr):
                if imported not in visited:
                    queue.append(imported)

        # Exclude self from dependency digest
        deps = sorted(visited - {file_path})
        if not deps:
            return ""

        hasher = hashlib.sha256()
        for dep in deps:
            hasher.update(dep.as_posix().encode("utf-8"))
            try:
                hasher.update(dep.read_bytes())
            except OSError:
                pass
        return hasher.hexdigest()

    def get_dependency_digest(self, file_path: Union[Path, str]) -> str:
        """Retrieve the computed dependency digest for file_path."""
        p = Path(file_path).resolve()
        return self.file_dependency_hashes.get(p, "")


__all__ = [
    "ProjectSymbolGraph",
    "resolve_module_path",
]

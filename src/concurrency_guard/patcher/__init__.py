"""Deterministic LibCST code auto-patcher for concurrency safety."""

from concurrency_guard.patcher.cst_fixer import (
    IdempotencyHeaderTransformer,
    IntegrityErrorGuardTransformer,
    PatchResult,
    PatchSkip,
    WithForUpdateTransformer,
    apply_all_fixes,
    apply_all_fixes_with_report,
    apply_with_for_update_fix,
    fix_file,
)
from concurrency_guard.patcher.diff_utils import (
    DiffGenerator,
    DiffResult,
    colorize_diff,
    generate_unified_diff,
    validate_patch_syntax,
)

__all__ = [
    "DiffGenerator",
    "DiffResult",
    "IdempotencyHeaderTransformer",
    "IntegrityErrorGuardTransformer",
    "PatchResult",
    "PatchSkip",
    "WithForUpdateTransformer",
    "apply_all_fixes",
    "apply_all_fixes_with_report",
    "apply_with_for_update_fix",
    "colorize_diff",
    "fix_file",
    "generate_unified_diff",
    "validate_patch_syntax",
]

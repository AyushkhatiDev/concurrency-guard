# ConcurrencyGuard (`cguard`)

[![PyPI version](https://img.shields.io/pypi/v/concurrency-guard.svg)](https://pypi.org/project/concurrency-guard/)
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Deterministic AST static analysis, runtime race verification, and auto-patching engine for Python FastAPI and SQLAlchemy backends.**

![ConcurrencyGuard Demo](demo_2.gif)

---

## The Problem vs. The `cguard` Solution

| Vulnerability Vector | Linters (Ruff, Flake8) | AI / LLM Code Reviewers | `cguard` |
|:---|:---|:---|:---|
| **Unlocked Read-Modify-Write** (`CG-001`) | ❌ Blind to DB semantics | ⚠️ Hallucinates, misses context | ✅ **Deterministic AST detection** |
| **Missing Idempotency Headers** (`CG-002`) | ❌ Ignored | ⚠️ High latency, non-deterministic | ✅ **Sub-millisecond AST verification** |
| **Async Loop N+1 Explode** (`CG-003`) | ❌ Unchecked | ⚠️ Inconsistent pattern matching | ✅ **Local control-flow AST traversal** |
| **Check-Then-Act Uniqueness Races** (`CG-004`) | ❌ Ignored | ⚠️ Frequently missed | ✅ **Catch-integrity validation** |
| **Celery Retry Duplication** (`CG-005`) | ❌ Ignored | ⚠️ Misses task retry mechanics | ✅ **Decorator & kwarg audit** |
| **Empirical Exploit Verification** | ❌ None | ❌ Cannot execute code | ✅ **`asyncio.Barrier` stress engine** |
| **Deterministic Code Remediation** | ⚠️ Style fixes only | ⚠️ Introduces syntax regressions | ✅ **Zero-regression `LibCST` patcher** |

Modern AI agents and developers write fast asynchronous endpoints, but routinely introduce critical race conditions: forgetting `.with_for_update()` row-level locks on balance deductions, omitting `Idempotency-Key` headers on mutating POST routes, or executing queries inside loops. 

Standard linters only validate syntax, while LLM-based reviewers are slow, non-deterministic, cost money per token, and miss non-local control flow races. **`cguard` runs 100% locally with zero external API calls**, using pure Python AST analysis to catch race conditions in milliseconds and providing runtime proof via synchronized barrier stress testing.

---

## Installation

```bash
pip install concurrency-guard
```

---

## Quick Start

### 1. Scan your codebase for concurrency vulnerabilities
Analyze files or entire directories in milliseconds with zero false positives:

```bash
# Scan a single route or module
cguard scan app/routers/wallet.py

# Scan an entire repository (auto-excludes virtualenvs, migrations, and build caches)
cguard scan src/
```

### 2. Verify race conditions empirically at runtime
Launch synchronized concurrent workers via `asyncio.Barrier` to mathematically prove whether an endpoint preserves or violates state invariants under high concurrency:

```bash
cguard verify examples/vulnerable_wallet.py --workers 20
```

```text
❌ CONCURRENCY INVARIANT VIOLATED (RACE PROVEN)
Target Endpoint: POST /wallet/withdraw
Concurrent Barrier Workers: 20
Initial Balance: $50
Successful Withdrawals ($50 each): 20
Final Resulting Balance: $-950 (Double-spend exploit confirmed!)
```

### 3. Automatically patch vulnerabilities in-place
Safely rewrite source code using `LibCST` syntax-tree transformations:

```bash
# Preview patch diff (dry-run)
cguard fix app/routers/wallet.py

# Write deterministic fixes directly to disk
cguard fix app/routers/wallet.py --write
```

---

## Supported Vulnerability Rules

| Rule ID | Rule Name | Trigger Condition | Automated Remediation (`LibCST`) |
|:---|:---|:---|:---|
| **`CG-001`** | **Unlocked Read-Modify-Write Race** | Route queries state (`select`, `db.scalar`, `session.get`), mutates an attribute, and commits without `.with_for_update()` locking. | Appends `.with_for_update()` row lock to the query chain. |
| **`CG-002`** | **Missing Idempotency Guard on POST** | Mutating `@app.post` or `@router.post` endpoint executes database writes without an `Idempotency-Key` parameter. | Injects `idempotency_key: str = Header(..., alias="Idempotency-Key")` into endpoint parameters. |
| **`CG-003`** | **Async Loop N+1 Query Explode** | Query operations (`.execute()`, `.scalar()`, `.scalars()`, `.get()`) called directly inside a `for` or `async for` loop body. | Flags query explosion; suggests eager loading via `joinedload` / `selectinload`. |
| **`CG-004`** | **Check-Then-Act Uniqueness Race** | Route checks existence via `select()`, executes `db.add()`, and commits without wrapping in a `try...except IntegrityError` handler. | Wraps commit in `try...except IntegrityError` with rollback. |
| **`CG-005`** | **Non-Idempotent Celery Retry Task** | Celery task configured with retries (`autoretry_for`, `max_retries`) executes mutations without `acks_late=True` or an idempotency lock. | Recommends `acks_late=True` and distributed deduplication lock before side-effects. |

---

## Architecture

`concurrency-guard` operates entirely offline and locally with zero external network or LLM dependencies:

- **Static Scanner (`ast`)**: Recursively walks Python Abstract Syntax Trees to identify dangerous state-mutation patterns across control flow, function parameters, loop constructs, and decorator metadata.
- **Runtime Verification Engine (`asyncio.Barrier`)**: Uses dynamic introspection and payload synthesis to seed isolated test states, synchronizing 20+ coroutines to hit endpoints at the exact same microsecond to prove state corruption.
- **Auto-Patcher (`libcst`)**: Performs lossless, Concrete Syntax Tree transformations that preserve comments, formatting, and indentation while injecting locks and error guards.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

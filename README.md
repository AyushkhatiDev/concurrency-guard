# ConcurrencyGuard (`cguard`)

[![PyPI version](https://img.shields.io/pypi/v/concurrency-guard.svg)](https://pypi.org/project/concurrency-guard/)
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub](https://img.shields.io/badge/GitHub-AyushkhatiDev%2Fconcurrency--guard-181717?logo=github)](https://github.com/AyushkhatiDev/concurrency-guard)

**v2.0 — universal static concurrency analysis, semantic taint tracking, runtime race verification, and auto-patching for Python codebases.**

![ConcurrencyGuard Demo](demo.gif)

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
Analyze files or entire directories in milliseconds with deterministic, source-only checks:

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

### Headless function verification

Stress a plain Python callable without FastAPI, an ORM, or HTTP infrastructure.
The verifier imports the selected source file, synchronizes workers with an
`asyncio.Barrier` or `threading.Barrier`, and compares the observed numeric
shared-dictionary value with the value implied by completed workers.

```bash
cguard verify worker.py --headless --function update_shared_state --workers 20
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
| **`CG-006`** | **Async Shared-State Mutation** | An async function modifies a module-level list/dict/set without an async lock context. | Use `asyncio.Lock` around the critical section. |
| **`CG-007`** | **Threaded Built-in Mutation** | A thread target mutates module-level built-in state without a `threading.Lock`/`RLock`. | Protect the collection or use a queue. |
| **`CG-008`** | **Generic Read-Modify-Write Race** | An attribute/subscript is read into a local, transformed, then assigned back without synchronization. | Lock the entire RMW operation or use an atomic primitive. |
| **`CG-009`–`CG-010`** | **File-system Races** | Concurrent write-mode `open`/`aiofiles.open`, or a hard-coded temporary filename. | Serialize writes and use `tempfile` for task-local paths. |
| **`CG-011`–`CG-012`** | **Cache Check-Then-Act** | Redis or Memcached get/set state transitions lack an atomic cache operation. | Use Redis `SET NX`, Lua, or Memcached atomic increment/CAS. |
| **`CG-013`** | **Lock-order Deadlock** | Two locks are acquired in opposite nesting orders in one module. | Establish and enforce one global lock order. |
| **`CG-014`** | **Inter-procedural Shared-state Race** | A local or imported function call chain reaches a cross-file function that mutates module shared state. | Propagate a synchronization boundary through the chain or make the leaf operation atomic. |
| **`CG-015`** | **Tainted Shared-state Mutation** | A reference to global, class-level, singleton, or Redis shared state flows through locals/callees and is mutated without a lock. | Lock the complete operation or use an atomic primitive. |

`cguard fix --write` can remediate CG-006, CG-007, and CG-009 in addition to the
database rules: it injects the required standard-library lock import and wraps
the flagged mutation, or wraps a write-mode file context in `filelock.FileLock`.

---

## Architecture

`concurrency-guard` operates entirely offline and locally with zero external network or LLM dependencies:

- **Static Scanner (`ast`)**: Recursively walks Python Abstract Syntax Trees to identify dangerous state-mutation patterns across control flow, function parameters, loop constructs, and decorator metadata.
- **Project Call Graph (`ast`)**: Resolves local functions and import aliases across the scanned source set, then propagates shared-state hazards to every transitive caller without importing or executing application code.
- **Semantic Taint Tracking (`ast`)**: Propagates shared-memory references through local aliases and resolved call arguments, identifying unprotected mutation sinks in asynchronous or threaded execution contexts.
- **Runtime Verification Engine**: Exercises FastAPI endpoints or raw Python functions using synchronized `asyncio.Barrier` and `threading.Barrier` workers to empirically demonstrate state corruption.
- **Auto-Patcher (`libcst`)**: Performs lossless, Concrete Syntax Tree transformations that preserve comments, formatting, and indentation while injecting locks and error guards.

### Custom rules

Teams can add checks for proprietary clients and frameworks without changing `cguard` source. Pass a YAML file with `--rules`:

```yaml
rules:
  - id: ACME-001
    function: acme_cache.get
    modifies: account.balance
    without_context: account_lock
    message: Acme cache balance updates must be guarded.
    fix: Use `async with account_lock:` around the update.
```

```bash
cguard scan src/ --rules concurrency-rules.yml
```

The DSL is intentionally declarative: `function`/`call` matches a call name,
`modifies`/`variable` matches an assignment target, and `without_context`/
`without_lock` suppresses the result when a matching `with` or `async with`
context exists.

## Source and releases

Source, issues, and release history are maintained at
[AyushkhatiDev/concurrency-guard](https://github.com/AyushkhatiDev/concurrency-guard).

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

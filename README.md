<div align="center">

# ConcurrencyGuard (`cguard`) — v2.6.1

### The Universal Semantic SAST, Empirical Race Verifier & Lossless Auto-Patcher for Python

[![PyPI version](https://img.shields.io/pypi/v/concurrency-guard.svg)](https://pypi.org/project/concurrency-guard/)
[![Python Version](https://img.shields.io/badge/python-3.10%2B%20%7C%20analyzes%203.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Test Suite](https://img.shields.io/badge/tests-166%2B%20passing-brightgreen.svg)](https://github.com/AyushkhatiDev/concurrency-guard)
[![Static Typing](https://img.shields.io/badge/typing-mypy%20--strict-blueviolet.svg)](https://github.com/python/mypy)
[![Zero External APIs](https://img.shields.io/badge/AI%20APIs-100%25%20Offline%20%7C%20Zero%20Calls-success.svg)](https://github.com/AyushkhatiDev/concurrency-guard)
[![Official Website](https://img.shields.io/badge/Website-concurrencyguard.dev-FF4D1C?logo=googlechrome&logoColor=white)](https://concurrencyguard.dev)
[![GitHub](https://img.shields.io/badge/GitHub-AyushkhatiDev%2Fconcurrency--guard-181717?logo=github)](https://github.com/AyushkhatiDev/concurrency-guard)

<br/>

![ConcurrencyGuard Demo](./demo.gif)

<br/>

**Deterministic AST static analysis, inter-procedural taint propagation, microsecond barrier verification, and compiler-grade LibCST code repair for Python backends.**  
Natively securing **FastAPI**, **Django ORM**, **SQLAlchemy 2.0**, **Celery**, **Redis / Memcached**, `asyncio.TaskGroup`, `anyio`, and multi-threaded architectures.

Explore interactive race simulations, rule breakdowns, and live AST patches at **[concurrencyguard.dev](https://concurrencyguard.dev)**.

</div>

## 🚀 What's New in v2.6.0

`cguard` v2.6.0 expands rule coverage from 16 to **21 enterprise concurrency rules**, adds atomic LibCST `F()` expression code repair, and introduces multi-core parallel scanning:

1. **New Concurrency Rules (`CG-017` – `CG-021`):**
   - **`CG-017` (Django Atomic `F()` Expression Optimization):** Detects in-memory model arithmetic before `.save()` / `.asave()` and suggests lock-free database-level `F()` expressions.
   - **`CG-018` (Distributed Lock TTL & Unsafe Release):** Flags raw `redis.delete(lock_key)` calls that lack token ownership verification, preventing accidental release of another worker's expired lock.
   - **`CG-019` (FastAPI `BackgroundTasks` DB Session Leak):** Catches request-scoped database sessions passed to background tasks that outlive the HTTP request lifecycle.
   - **`CG-020` (Unbounded Lock Held Across Network I/O):** Identifies slow HTTP/network requests executed while holding a lock or active database transaction, eliminating connection pool exhaustion.
   - **`CG-021` (Generator Lock Leak):** Flags `yield` inside a `with lock:` context manager that leaves locks held indefinitely across generator suspension points.
2. **LibCST Auto-Patching for `CG-017`:** Automatically transforms in-memory Django increments/decrements (`wallet.balance -= amount`) into atomic database updates (`wallet.balance = F("balance") - amount`) and automatically injects `from django.db.models import F`.
3. **High-Throughput Multi-Core Parallel Scanning:** Added `--workers` / `-w` CLI flag for `cguard scan` with multi-threaded execution and SQLite WAL mode (`PRAGMA journal_mode=WAL;`), providing instantaneous scans on massive monorepos.
4. **Structured Concurrency Detection (v2.5.0):** Deep AST awareness of `asyncio.TaskGroup`, `anyio.create_task_group()`, and `BackgroundTasks.add_task()`.
5. **Compiler-Grade Deadlock Analysis (v2.5.0):** Intra-function and inter-procedural self-deadlock detection, smart `RLock` suppression, and sync-lock detection inside `async def` routines.
3. **SQLAlchemy 2.0 Fluent Chains & LibCST Precision:** Full support for `select(...).where(...).with_for_update()` fluent chains with precision AST transformer targeting inner `select(...)` calls inside `session.execute(...)` and `session.scalar(...)`.
4. **Git-Diff Aware Incremental Scanning:** `--changed-only` and `--base-ref` CLI flags for ultra-fast local workflows and PR checks.
5. **Native Pre-Commit Hooks:** Seamless `.pre-commit-hooks.yaml` integration for CI and local git hooks.

Configure repository defaults in `pyproject.toml`; command-line options still
take precedence where applicable:

```toml
[tool.cguard]
exclude = ["generated", "vendor"]
ignore = ["CG-003"]
rules_file = "cguard-rules.yml"
cache = true
```

For GitHub's Security tab or other code-scanning systems, emit SARIF 2.1.0:

```bash
cguard scan src --format sarif > cguard.sarif
```

---

## ⚡ What is `cguard` in 30 Seconds?

### The Core Problem: The Silent $50 Double-Withdrawal Bug
When two HTTP requests hit your web service at the exact same millisecond:
1. **Thread A** reads the user's balance: `$100`.
2. **Thread B** reads the user's balance: `$100`.
3. **Thread A** computes `$100 - $50 = $50` and writes it to the database.
4. **Thread B** computes `$100 - $50 = $50` and overwrites the balance in the database.

**The Result:** The customer withdrew **$100 total**, but their balance was only debited **$50**. Your application just suffered an **Unlocked Read-Modify-Write (RMW) Race Condition**.

### Why Existing Tools Fail
- **Linters (`ruff`, `flake8`)**: Only enforce syntax formatting, unused imports, or cyclomatic complexity. They are completely blind to database transactions, row locking, and shared memory.
- **AI / LLM Code Reviewers**: Suffer from non-deterministic hallucinations, high latency, recurring token fees, and context-window fragmentation. They cannot trace variables across files and cannot mathematically execute code.
- **Production APMs & Loggers**: Only observe the damage *after* financial loss or state corruption has already occurred.

### `cguard`'s 3-Step Magic: Before, Detection, and Fix

````carousel
```python
# STEP 1: The Vulnerable Code (Django ORM or FastAPI / SQLAlchemy)
from django.db import transaction

def withdraw(user_id: int, amount: float):
    with transaction.atomic():
        # VULNERABILITY (CG-016): Missing row lock!
        wallet = User.objects.get(id=user_id)
        w = wallet  # Aliased reference
        w.balance -= amount
        w.save()
```
<!-- slide -->
```text
# STEP 2: The Detection & Empirical Proof
$ cguard scan src/
Found 1 concurrency security issue:
  [CG-016] src/services/wallet.py:6: withdraw
  Django Unlocked Read-Modify-Write: a model fetched through objects
  is mutated and saved without a row lock held by transaction.atomic().
  Fix: Use User.objects.select_for_update().get(...)

$ cguard verify src/services/wallet.py --headless --function withdraw --workers 20
❌ HEADLESS CONCURRENCY INVARIANT VIOLATED (RACE PROVEN)
  Target Function: withdraw | Synchronization Engine: asyncio.Barrier (20 workers)
  Initial Balance: $50 | Successful Withdrawals: 20
  Final Resulting Balance: -$950.00 (Double-spend exploit confirmed!)
```
<!-- slide -->
```python
# STEP 3: The Lossless LibCST Auto-Patch
from django.db import transaction

def withdraw(user_id: int, amount: float):
    with transaction.atomic():
        # PRESERVED: Original comments and formatting untouched!
        wallet = User.objects.select_for_update().get(id=user_id)
        w = wallet
        w.balance -= amount
        w.save()
```
````

---

## 🌐 Interactive Web Sandbox & Race Explorer ([concurrencyguard.dev](https://concurrencyguard.dev))

Explore ConcurrencyGuard interactively in your browser at **[concurrencyguard.dev](https://concurrencyguard.dev)** — a full-featured web companion and visual evidence platform for understanding and debugging Python concurrency races.

[![ConcurrencyGuard Website Preview](https://img.shields.io/badge/Live%20Demo-concurrencyguard.dev-FF4D1C?style=for-the-badge&logo=googlechrome&logoColor=white)](https://concurrencyguard.dev)

### What You Can Explore on the Website:

1. **Interactive Race Condition Simulator:**
   - Step through a real-world financial double-withdrawal timeline (Request A vs. Request B) frame-by-frame.
   - Switch between **Unsafe Execution** (showing interleaving reads, conflicting writes, and balance overdrafts) and **Serialized Execution** (demonstrating how `SELECT FOR UPDATE` blocks Request B until Request A commits).
   - Visualize transaction boundaries, lock hold durations, and race windows with millisecond timestamps.

2. **Interactive AST Bug Explorer:**
   - Compare vulnerable code patterns and lossless LibCST patches side-by-side across major Python ecosystems:
     - **Django ORM (`CG-016`):** Unlocked `User.objects.get()` vs. `@transaction.atomic` + `select_for_update()`.
     - **FastAPI (`CG-001`):** Unlocked `await db.get(...)` vs. `select(...).with_for_update()`.
     - **Celery (`CG-005`):** Non-idempotent task retry vs. `acks_late=True` with distributed idempotency locks.
     - **SQLAlchemy 2.0 (`CG-004`):** Check-then-act uniqueness races vs. `IntegrityError` atomic handling.
     - **asyncio (`CG-006`):** Unsynchronized shared cache mutations vs. `async with asyncio.Lock():`.
   - Hover over highlighted hot lines to inspect precise AST taint propagation and trigger conditions.

3. **Searchable 16-Rule Security Catalog:**
   - Filter and search the complete catalog of concurrency rules by ecosystem (**FastAPI**, **Django**, **Celery**, **SQLAlchemy**, **Redis**, **asyncio**, **Threads**, **Filesystem**).
   - View severity ratings, AST detection logic, rationale, and whether the rule supports automated LibCST patch generation.

4. **Real Microsecond Concurrency Engine Telemetry:**
   - Deep dive into `cguard`'s 4-stage pipeline: AST Taint Visitor, Bipartite Lock-Order Cycle Detector, `asyncio.Barrier` Headless Verifier, and SQLite SHA-256 Incremental Cache.
   - Live benchmarks comparing cold vs. hot cached scan speeds (24ms vs. 1.2ms).

5. **GitHub App Early Access:**
   - Join the early access waitlist for the ConcurrencyGuard GitHub App to automatically review incoming PRs, post inline thread-safety comments, and propose verified LibCST patches.

---

## ⚖️ The Comparison Matrix: Why `cguard` Wins

*(Browse the full interactive rule index and test cases at [concurrencyguard.dev](https://concurrencyguard.dev))*

| Concurrency Vector | Rule ID | Syntax Linters (`ruff`, `flake8`) | AI / LLM Code Reviewers | `cguard` Semantic SAST (v2.6.0) |
|:---|:---:|:---:|:---:|:---:|
| **SQLAlchemy Unlocked RMW** | `CG-001` | ❌ Blind to DB semantics | ⚠️ Hallucinates, misses context | ✅ **Deterministic AST query-chain audit** |
| **Missing Idempotency Keys** | `CG-002` | ❌ Ignored | ⚠️ Inconsistent pattern matching | ✅ **Sub-millisecond route signature check** |
| **Async Loop N+1 Explode** | `CG-003` | ❌ Unchecked | ⚠️ Fails on multi-line comprehensions | ✅ **Local control-flow AST traversal** |
| **Check-Then-Act Uniqueness** | `CG-004` | ❌ Ignored | ⚠️ Frequently missed | ✅ **Catch-integrity & rollback validation** |
| **Celery Retry Duplication** | `CG-005` | ❌ Ignored | ⚠️ Misses task retry mechanics | ✅ **Decorator `acks_late` & dedup audit** |
| **Async Shared-State Mutation** | `CG-006` | ❌ Ignored | ⚠️ Fails on module-level globals | ✅ **Statement-level `async with lock:` audit** |
| **Threaded Collection Mutation** | `CG-007` | ❌ Ignored | ⚠️ Overlooks multi-threaded entry | ✅ **Thread-target synchronization check** |
| **In-Memory RMW Data Races** | `CG-008` | ❌ Ignored | ⚠️ Blind to attribute reassignment | ✅ **Semantic state-flow RMW tracking** |
| **Concurrent File Overwrite** | `CG-009` | ❌ Ignored | ⚠️ Ignores multi-worker process I/O | ✅ **`filelock.FileLock` validation** |
| **Predictable Tempfile Collision** | `CG-010` | ⚠️ Flags path string only | ⚠️ Recommends unsafe workarounds | ✅ **Enforces `tempfile.NamedTemporaryFile`** |
| **Redis Check-Then-Act Race** | `CG-011` | ❌ Ignored | ⚠️ Recommends fragile locks | ✅ **Atomic primitive audit (`SET NX`, Lua)** |
| **Non-Atomic Cache Invalidation** | `CG-012` | ❌ Ignored | ⚠️ Misses distributed commit timing | ✅ **Two-phase invalidation verification** |
| **Lock-Order Deadlocks** | `CG-013` | ❌ Ignored | ❌ Incapable of bipartite analysis | ✅ **Bipartite directed lock graph analysis** |
| **Cross-File Call-Chain Races** | `CG-014` | ❌ Single-file scope only | ❌ Exceeds token context window | ✅ **Project-wide Inter-Procedural Call Graph** |
| **Abstracted Shared-State Taint** | `CG-015` | ❌ Ignored | ⚠️ Loses variable provenance | ✅ **Forward Data-Flow Taint Propagation** |
| **Django ORM Unlocked RMW** | `CG-016` | ❌ Ignored | ⚠️ Misses ORM transaction scope | ✅ **Scope-aware `select_for_update` audit** |
| **Django In-Memory Arithmetic** | `CG-017` | ❌ Ignored | ⚠️ Recommends locks over SQL | ✅ **Lock-free atomic `F()` expression audit** |
| **Distributed Lock Unsafe Delete** | `CG-018` | ❌ Ignored | ⚠️ Overlooks TTL expiration | ✅ **Token-checked Lua & lock manager audit** |
| **BackgroundTasks Session Leak** | `CG-019` | ❌ Ignored | ⚠️ Blind to async task lifetimes | ✅ **Request-scoped DB session lifetime audit** |
| **Unbounded Lock Across I/O** | `CG-020` | ❌ Ignored | ⚠️ Misses pool exhaustion risk | ✅ **Connection-pool boundary validation** |
| **Generator Lock Leak (`yield`)** | `CG-021` | ❌ Ignored | ⚠️ Misses generator suspension | ✅ **Context-aware yield point audit** |
| **Empirical Runtime Verification** | — | ❌ None | ❌ Cannot execute or stress code | ✅ **Synchronized `Barrier` stress engine** |
| **Deterministic Code Remediation** | — | ⚠️ Style fixes only | ⚠️ Introduces syntax regressions | ✅ **Lossless `LibCST` + `ast.parse` preflight** |

---

## 🏛️ End-to-End Compiler Architecture

`concurrency-guard` operates as a deterministic, multi-stage compiler pipeline designed for 100% offline, zero-false-positive execution.

```text
  +----------------------------------------------------------------------------------------------------+
  |                                CONCURRENCYGUARD COMPILER PIPELINE                                  |
  +----------------------------------------------------------------------------------------------------+
                                                     |
                                            [ Source Files (.py) ]
                                                     |
                                                     v
                            +--------------------------------------------------+
                            | 1. SHA-256 SQLite Incremental Cache Engine       |
                            |    (.concurrency_guard_cache.db)                 |
                            |    Hash: (file_bytes + engine_ver + config_hash) |
                            +--------------------------------------------------+
                                    |                                  |
                              [Cache Hit]                         [Cache Miss]
                                    |                                  v
                                    |         +------------------------------------------------+
                                    |         | 2. Tokenize Lexer Suppression Filter           |
                                    |         |    (Extract # cg:ignore line/block/file scopes)|
                                    |         +------------------------------------------------+
                                    |                                  |
                                    |                                  v
                                    |         +------------------------------------------------+
                                    |         | 3. AST Parser & Inter-Procedural Call Graph    |
                                    |         |    (Cross-file imported symbols & call chains) |
                                    |         +------------------------------------------------+
                                    |                                  |
                                    |                                  v
                                    |         +------------------------------------------------+
                                    |         | 4. Semantic Data-Flow & Deep Alias Tracker     |
                                    |         |    (Transitive aliases: wallet -> w1 -> w2)    |
                                    |         +------------------------------------------------+
                                    |                                  |
                                    |                                  v
                                    |         +------------------------------------------------+
                                    |         | 5. Context-Aware Synchronization Stack         |
                                    |         |    (with/async with lock, atomic() scopes)     |
                                    |         +------------------------------------------------+
                                    |                                  |
                                    +-----------------> + <------------+
                                                        |
                                                        v
                                    +--------------------------------------------------+
                                    | 6. Deterministic Findings Engine                 |
                                    |    (CG-001 through CG-016 Diagnostic Output)     |
                                    +--------------------------------------------------+
                                         /                                  \
                                        v                                    v
     +-----------------------------------------------------+   +-----------------------------------------------------+
     | 7. Headless Runtime Stress Verifier                 |   | 8. Lossless LibCST Auto-Patcher                     |
     |    - asyncio.Barrier & threading.Barrier            |   |    - In-Memory ANSI Diff Generator (--diff)         |
     |    - Microsecond release of up to 100 workers       |   |    - Preflight ast.parse() Syntax Validation        |
     |    - Mathematical proof of invariant violations     |   |    - Zero-regression disk write (--write)           |
     +-----------------------------------------------------+   +-----------------------------------------------------+
```

### The 8 Architectural Pillars of `cguard`

#### 1. Inter-Procedural Call Graph Analysis (`CG-014`)
Real-world concurrency defects rarely live within a single function. A FastAPI route or Celery task calls an application service, which calls a domain repository, which mutates a module-level dictionary or singleton cache.  
`cguard` constructs a project-wide symbol graph across files. It resolves imported module aliases, tracks caller-to-callee dependencies, and transitively propagates hazards from deep leaf mutation sinks back up to the exposed entry points.

#### 2. Forward Data-Flow Semantic Taint Tracking (`CG-015`)
Simple pattern matching fails when shared mutable memory is assigned to temporary variables, passed through arguments, or returned from helper methods.  
`cguard` implements a forward data-flow taint engine. It labels shared mutable state (module globals, class caches, Redis connections, singleton pools) at its declaration and tracks taint propagation through variable assignments, tuple unpacking, and function invocations. A vulnerability is flagged whenever a tainted reference reaches an unguarded mutation sink (`AugAssign`, `.append()`, `.pop()`, `.set()`, `.update()`).

#### 3. Deep Transitive Alias & Context-Aware Lock Detection (`CG-006`, `CG-007`, `CG-016`)
In v2.3.0, `ConcurrencyASTVisitor` maintains a stateful scoped alias dictionary (`self.aliases`) and a synchronized context stack (`self.context_stack`):
- **Transitive Aliases:** When a vulnerable fetch is assigned (`wallet = User.objects.get(...)`) and reassigned (`w1 = wallet`, `w2 = w1`), the taint is preserved. An in-place mutation on `w2.balance -= 50` immediately triggers `CG-016` on `w2` without requiring `.save()`.
- **Reassignment Invalidation:** If an aliased variable is reassigned to a safe non-ORM object (`w = make_safe_dummy()`), taint is cleared immediately to prevent false positives.
- **Statement-Level Lock Awareness:** For `CG-006` and `CG-007`, the engine inspects statement blocks against the active lock stack. If all mutations to a shared dictionary are wrapped in `async with lock:` (or `with lock:`), the rule is cleanly suppressed.

#### 4. Thread-Safe Incremental SQLite Caching Engine (`cguard scan --cache`)
For multi-thousand-file enterprise codebases and fast CI/CD runs, `CacheManager` provides persistent incremental caching backed by a thread-safe SQLite database (`.concurrency_guard_cache.db`):
- **Cache Key Calculation:** Computes a composite SHA-256 hash:
  $$\text{CacheKey} = \text{SHA256}(\text{file\_bytes} + \text{scanner\_version} + \text{rules\_config\_hash})$$
- **Sub-Millisecond Speed:** Unchanged files skip AST parsing and taint tracking entirely, returning cached findings instantly while auto-invalidating any file whose contents or active rule configurations change.

#### 5. Lexer-Driven `# cg:ignore` Suppression Engine
Unlike regex-based linters that accidentally trigger on comments embedded inside multiline strings or SQL queries, `cguard`'s `SuppressionFilter` uses Python's standard `tokenize` module to extract true comment tokens:
- **Line-level suppression:**
  ```python
  wallet.balance -= 50  # cg:ignore[CG-016] rationale="Protected upstream by orchestrator lock"
  ```
- **Block-level suppression:**
  ```python
  # cg:ignore-start[CG-006, CG-007]
  shared_cache[key] = val
  # cg:ignore-end[CG-006, CG-007]
  ```
- **File-level suppression:**
  ```python
  # cg:ignore-file[CG-001, CG-002]
  ```

#### 6. Non-Destructive In-Memory Diffs & Preflight AST Validation (`cguard fix --diff`)
Automated security remediation must never corrupt source code. `cguard fix` runs in-memory transformations using `difflib.unified_diff` with basic ANSI color formatting:
- **Preflight AST Syntax Gate:** Before printing a diff or committing changes to disk, the patched string is compiled in memory using Python's `ast.parse()`. If a syntax error is detected, the patch is aborted immediately.
- **Deterministic CLI Exit Contract:** Returns `0` on successful, syntax-validated diffs and `1` on syntax aborts, guaranteeing zero broken builds in automated pipelines.

#### 7. Empirical Runtime & Headless Barrier Verification (`cguard verify`)
Static analysis finds theoretical races; `cguard verify` mathematically proves them:
- **No Web Server Needed (`--headless`):** Dynamically imports raw Python async or threaded callables directly in memory.
- **Microsecond Synchronization:** Uses synchronized barriers (`asyncio.Barrier` or `threading.Barrier`) to align up to 100 concurrent worker threads or coroutines, releasing them at the exact same microsecond.
- **State Invariant Validation:** Automatically verifies whether final state matches expected increments or debit amounts, exposing balance double-spends and lost updates.

#### 8. Lossless Concrete Syntax Tree Auto-Patching (`cguard fix --write`)
Fixing concurrency bugs with naive regex replaces breaks formatting and strips comments. `cguard` manipulates full Concrete Syntax Trees using `libcst`:
- **Deterministic Transformers:** Injects `.with_for_update()`, `.select_for_update()`, `asyncio.Lock()`, `threading.Lock()`, `filelock.FileLock`, and `try...except IntegrityError` rollback handlers.
- **100% Comment & Layout Preservation:** Every docstring, inline `# comment`, indent, and whitespace character is preserved byte-for-byte.

---

## 📈 Engineering Evolution: Built up to v2.3.0

| Milestone | Key Architectural Upgrades |
|:---|:---|
| **v1.0.0** | Initial FastAPI & SQLAlchemy AST pattern scanner (`CG-001` through `CG-005`). |
| **v2.0.0** | HTTP runtime verification engine (`asyncio.Barrier`) and initial `libcst` auto-patcher. |
| **v2.1.0** | Inter-Procedural Call Graph (`CG-014`), Forward Data-Flow Taint Tracker (`CG-015`), Django ORM support (`CG-016`), and Framework-Free Headless Verification (`cguard verify --headless`). |
| **v2.2.0** | Conservative lexical control-flow path merging, dead-code isolation, and AST syntax validation. |
| **v2.3.0** *(Current)* | **SQLite Incremental Scan Caching** (`--cache`), **Tokenized `# cg:ignore` Suppression Directives**, **Non-Destructive In-Memory Unified Diffs** (`--diff`), **Deep Transitive Alias Taint Tracking**, and **Context-Aware Lock Stacks** (`async with lock:` suppression). |

---

## 🚀 Installation

Install `concurrency-guard` via `pip` or `uv`:

```bash
# Standard pip installation
pip install concurrency-guard

# Or install as an isolated global tool with uv
uv tool install concurrency-guard
```

*Compatibility: Requires Python 3.10+ runtime; analyzes and auto-patches codebases written in Python 3.9 through 3.13.*

---

## 💻 Comprehensive CLI Reference

### 1. `cguard scan` — Static Vulnerability Analysis
Scan files, packages, or full repositories for concurrency bugs.

```bash
# Scan a specific file
cguard scan src/services/wallet.py

# Scan an entire repository (auto-excludes .venv, node_modules, migrations, and build dirs)
cguard scan src/

# Run ultra-fast incremental scanning using SQLite caching
cguard scan src/ --cache

# Scan ONLY files modified in git (staged, unstaged, or untracked)
cguard scan src/ --changed-only

# Compare against a git base branch (e.g. in CI or PR checks)
cguard scan src/ --base-ref origin/main

# Specify a custom cache database path
cguard scan src/ --cache --cache-path .concurrency_guard_cache.db

# Output structured JSON for automated security dashboards or CI/CD
cguard scan src/ --format json

# Enforce custom organization-specific YAML rules
cguard scan src/ --rules concurrency-rules.yml
```

#### Example Output:
```text
Scanning target: src/ ...
Loaded 16 built-in rules. Cache: ENABLED (.concurrency_guard_cache.db)

Found 2 concurrency security issues:

  [CG-001] src/routers/billing.py:42: checkout
  Unlocked Read-Modify-Write Race Condition: fetched state is mutated and committed without a row lock.
  Suggested Fix: Append .with_for_update() to the SELECT query.

  [CG-016] src/services/account.py:19: transfer_balance
  Django Unlocked Read-Modify-Write: model fetched through objects is mutated and saved without select_for_update().
  Suggested Fix: Fetch row with .objects.select_for_update().get(...) inside transaction.atomic().

Scan completed in 4.2ms. (14 files cached, 2 files analyzed)
```

---

### 2. `cguard verify` — Empirical Race Condition Stress-Testing
Prove that a theoretical race condition actually allows exploits at runtime.

#### Option A: FastAPI HTTP Endpoint Stress Test
```bash
cguard verify examples/vulnerable_wallet.py --workers 20 --initial-balance 50 --withdrawal 50
```

```text
======================================================================
  CONCURRENCYGUARD RUNTIME VERIFICATION SUITE
======================================================================
Target Endpoint: POST /wallet/withdraw
Spawned Workers: 20 concurrent threads
Barrier Synchronization: ACTIVE (Release microsecond aligned)

[Worker 01] Status: 200 OK | Balance: $0.00
[Worker 02] Status: 200 OK | Balance: -$50.00
...
[Worker 20] Status: 200 OK | Balance: -$950.00

----------------------------------------------------------------------
❌ CONCURRENCY INVARIANT VIOLATED (RACE PROVEN)
  Expected Balance: $0.00 (Only 1 withdrawal should succeed)
  Observed Balance: -$950.00 (20 withdrawals succeeded)
  Exploit Status: CRITICAL DOUBLE-SPEND CONFIRMED
======================================================================
```

#### Option B: Headless Function Stress Test (No HTTP / No Server)
Stress-test raw async coroutines or standard threading functions in memory:

```bash
cguard verify src/workers/tasks.py --headless --function update_counter --workers 50
```

```text
======================================================================
  HEADLESS RUNTIME VERIFICATION SUITE
======================================================================
Target Callable: src.workers.tasks::update_counter
Concurrency Primitive: asyncio.Barrier (50 workers)

[+] Synchronizing 50 async coroutines at barrier threshold...
[+] Releasing barrier! All workers executed concurrently.

----------------------------------------------------------------------
❌ HEADLESS CONCURRENCY INVARIANT VIOLATED
  Expected Final Value: 50
  Observed Final Value: 18
  Lost Updates: 32 state modifications dropped due to race condition!
======================================================================
```

---

### 3. `cguard fix` — Lossless Concrete Syntax Tree Remediation
Repair identified concurrency vulnerabilities using compiler-grade `libcst` transformations.

```bash
# Preview the unified diff in memory without touching files (dry-run)
cguard fix src/services/wallet.py --diff

# Apply safe fixes directly to disk
cguard fix src/services/wallet.py --write

# Target only a specific rule
cguard fix src/services/wallet.py --rule CG-016 --write
```

#### Example Output (`cguard fix --diff`):
```diff
--- src/services/wallet.py (original)
+++ src/services/wallet.py (patched)
@@ -14,6 +14,6 @@
 def transfer(user_id: int, amount: float):
     with transaction.atomic():
         # Preserve original developer comments and indentation
-        wallet = User.objects.get(id=user_id)
+        wallet = User.objects.select_for_update().get(id=user_id)
         wallet.balance -= amount
         wallet.save()

Preflight AST Syntax Validation: PASSED (Syntax is 100% valid Python)
Zero files modified. Pass --write to apply changes to disk.
```

---

### 4. `cguard report` — CI/CD Markdown Security Audit
Generate GitHub-flavored Markdown summaries formatted for pull request summaries or security tickets:

```bash
cguard report src/ --output concurrency-report.md
```

---

## 📚 Complete 16 Vulnerability Rules Catalog

| Rule ID | Vulnerability Vector | Subsystem | AST Trigger Condition | Automated Remediation (`LibCST`) |
|:---:|:---|:---|:---|:---|
| **`CG-001`** | **Unlocked Read-Modify-Write Race** | SQLAlchemy / FastAPI | Route executes `select()` or `session.get()`, mutates an attribute, and calls `session.commit()` without `.with_for_update()`. | Injects `.with_for_update()` into query chain. |
| **`CG-002`** | **Missing Idempotency Guard on POST** | FastAPI / Starlette | Route decorated with `@app.post` or `@router.post` performs DB side effects without an `Idempotency-Key` parameter. | Injects `idempotency_key: str = Header(...)` parameter. |
| **`CG-003`** | **Async Loop N+1 Query Explosion** | AsyncIO / SQLAlchemy | Async database query calls (`.execute()`, `.scalar()`, `.get()`) executed inside `for` or `async for` loops. | Diagnostic warning recommending eager joinedload / selectinload. |
| **`CG-004`** | **Check-Then-Act Uniqueness Race** | SQLAlchemy / DB | Query checks record existence, calls `session.add()`, and commits without catching database `IntegrityError`. | Wraps commit in `try...except IntegrityError:` with rollback. |
| **`CG-005`** | **Non-Idempotent Celery Retry Task** | Celery Tasks | Retrying task decorator (`@task(autoretry_for=...)`) lacks `acks_late=True` or an idempotency lock check. | Recommends `acks_late=True` and distributed deduplication lock. |
| **`CG-006`** | **Async Shared-State Mutation** | `asyncio` Standard Lib | Coroutine mutates module-level collection (`dict`, `list`, `set`) outside an active `async with lock:` block. | Injects `asyncio.Lock()` and wraps mutation in `async with`. |
| **`CG-007`** | **Threaded Collection Mutation** | `threading` Standard Lib | Function passed as `threading.Thread(target=...)` mutates shared state without an active `with lock:` block. | Injects `threading.Lock()` and wraps mutation in `with`. |
| **`CG-008`** | **Generic In-Memory RMW Race** | Core Python Memory | Local variable reads attribute or subscript, performs transformation, and reassigns without synchronization. | Recommends atomic operation or lock-guarded block. |
| **`CG-009`** | **Concurrent File Overwrite Race** | Filesystem I/O | Concurrent writes via `open()` or `aiofiles.open()` in write/append mode without a filesystem lock. | Wraps file I/O context in `filelock.FileLock`. |
| **`CG-010`** | **Predictable Tempfile Collision** | OS Security | Static or predictable filename used under `/tmp` across concurrent task contexts. | Recommends `tempfile.NamedTemporaryFile` with randomized name. |
| **`CG-011`** | **Redis Check-Then-Act Race** | Redis / Caching | Key read (`redis.get()`) followed by write (`redis.set()`) without atomic primitives. | Recommends atomic `SET key value NX` or Lua scripting. |
| **`CG-012`** | **Non-Atomic Cache Invalidation** | Distributed Cache | DB write committed before or after cache eviction without two-phase transactional synchronization. | Recommends two-phase commit or atomic write-through. |
| **`CG-013`** | **Lock-Order Inversion Deadlock** | Concurrency Primitives | Multiple locks acquired in opposing order (`Lock A -> Lock B` vs `Lock B -> Lock A`) across execution paths. | Detects cycle and establishes strict global acquisition order. |
| **`CG-014`** | **Inter-Procedural Call-Chain Race** | Architecture / Call Graph | Route or worker calls an imported function whose transitive downstream calls mutate shared state without locks. | Traces cross-file call graph from route down to mutation sink. |
| **`CG-015`** | **Tainted Shared-State Mutation** | Semantic Data Flow | Mutable reference to global or singleton state passes through local aliases or args into unguarded mutations. | Traces taint propagation and isolates unguarded mutation sink. |
| **`CG-016`** | **Django ORM Unlocked RMW Race** | Django ORM | Django query (`objects.get()`, `filter().first()`) mutated and saved without `.select_for_update()`. | Injects `.select_for_update()` inside `transaction.atomic()`. |

---

## 🛠️ Custom Enterprise Rules (Declarative YAML DSL)

Enforce custom architectural policies across microservices without writing AST visitors. Create a `concurrency-rules.yml` file:

```yaml
rules:
  - id: ACME-001
    description: "Acme wallet balance updates must acquire the tenant lock"
    function: "acme_wallet.deduct"
    modifies: "wallet.balance"
    without_context: "tenant_lock"
    message: "Tenant balance mutation must be protected with `async with tenant_lock:`"
    fix: "Wrap balance deduction in `async with tenant_lock:`"

  - id: ACME-002
    description: "Internal Redis credit allocation must use Lua scripts"
    call: "redis_client.set"
    variable: "user_credits"
    without_lock: "redis_dist_lock"
    message: "Direct credit set detected. Use atomic Lua script or acquire `redis_dist_lock`."
```

Execute `cguard` using your custom rules:
```bash
cguard scan src/ --rules concurrency-rules.yml
```

---

## 🤖 CI/CD Integration: GitHub Actions

Add automated concurrency security testing to your pull request workflows:

```yaml
name: Concurrency Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  cguard-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install ConcurrencyGuard
        run: pip install concurrency-guard

      - name: Run Cached Concurrency Scan
        run: cguard scan src/ --cache

      - name: Generate PR Markdown Report
        if: failure()
        run: cguard report src/ >> $GITHUB_STEP_SUMMARY
```

---

## 🪝 Native Pre-Commit Hooks

`concurrency-guard` natively integrates with [pre-commit](https://pre-commit.com/) to block concurrency regressions before they reach your repository.

Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/AyushkhatiDev/concurrency-guard
    rev: v2.6.1
    hooks:
      - id: cguard-scan
      - id: cguard-fix-diff
```

- **`cguard-scan`**: Scans staged Python files for concurrency vulnerabilities.
- **`cguard-fix-diff`**: Previews suggested LibCST diffs in memory without modifying files on disk.

---

## 📄 License & Community

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

- **Official Website & Live Sandbox**: [concurrencyguard.dev](https://concurrencyguard.dev)
- **PyPI Package**: [pypi.org/project/concurrency-guard](https://pypi.org/project/concurrency-guard/)
- **Source Repository**: [github.com/AyushkhatiDev/concurrency-guard](https://github.com/AyushkhatiDev/concurrency-guard)
- **Issue Tracker**: [github.com/AyushkhatiDev/concurrency-guard/issues](https://github.com/AyushkhatiDev/concurrency-guard/issues)

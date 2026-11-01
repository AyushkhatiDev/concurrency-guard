# ConcurrencyGuard (`cguard`)

[![CI](https://github.com/AyushkhatiDev/concurrency-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/AyushkhatiDev/concurrency-guard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Deterministic AST + Runtime Concurrency & Idempotency Verifier for Python FastAPI, SQLAlchemy, and Celery Backends.**

---

## ⚡ Why ConcurrencyGuard?

Modern async Python services frequently suffer from silent concurrency bugs, double-spend race conditions, lost updates, and duplicate background tasks. Traditional linters only check syntax and type hints, while external LLM tools hallucinate or miss non-local control flow races.

**ConcurrencyGuard (`cguard`)** solves this with a **100% deterministic pipeline**:
1. **Pure AST Static Scanning**: Catches race patterns, missing idempotency keys, N+1 queries, uniqueness races, and unsafe Celery retry tasks.
2. **Runtime `asyncio.Barrier` Exploit Engine**: Proves race conditions empirically by synchronizing concurrent coroutines to hit endpoints at the exact same microsecond.
3. **Deterministic `LibCST` Auto-Patcher**: Safely rewrites code to apply database row locks (`.with_for_update()`), inject FastAPI `Idempotency-Key` headers, and wrap transactions in `IntegrityError` guards.
4. **Automated GitHub PR Reporter**: Emits rich Markdown comments with exploit proofs and diff previews for pull requests.

---

## 📋 Rule Catalog

| Rule ID | Name | Target / Trigger Condition | Automated Fix |
|:---|:---|:---|:---|
| **`CG-001`** | **Unlocked Read-Modify-Write Race** | Async route reads database state with `select()`, mutates an attribute, and calls `commit()` without `.with_for_update()` locking. | Appends `.with_for_update()` row-level locks via LibCST. |
| **`CG-002`** | **Missing Idempotency Guard** | Async `@app.post` or `@router.post` route mutates state without an `idempotency_key` parameter. | Injects `idempotency_key: str = Header(..., alias="Idempotency-Key")` into route parameters. |
| **`CG-003`** | **Async Loop N+1 Query Explode** | `db.execute(...)` or `session.execute(...)` call located directly inside a `for` or `async for` loop body. | Flags query explosion; suggests batching or eager loading (`joinedload`/`selectinload`). |
| **`CG-004`** | **Check-Then-Act Uniqueness Race** | Async route checks existence with `select()`, calls `add()`, and commits without catching `sqlalchemy.exc.IntegrityError`. | Wraps commit statements in `try...except IntegrityError` with session rollback. |
| **`CG-005`** | **Non-Idempotent Celery Retry Task** | Celery task (`@app.task`, `@shared_task`) with `autoretry_for` or `max_retries` executes mutations (`.add()`, `.commit()`, `.post()`) without `acks_late=True` or an idempotency lock. | Recommends `acks_late=True` and distributed deduplication lock before side-effects. |

---

## 🚀 Installation

```bash
# Clone and install in virtual environment
git clone https://github.com/AyushkhatiDev/concurrency-guard.git
cd concurrency-guard
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

To install with development and testing dependencies:
```bash
pip install -e ".[dev]"
```

---

## 🛠️ CLI Usage

### 1. `cguard scan` — Static AST Analysis
Scan files or entire directories for concurrency vulnerabilities:
```bash
# Scan a single file
cguard scan examples/vulnerable_wallet.py

# Scan an entire codebase
cguard scan src/
```

### 2. `cguard verify` — Runtime `asyncio.Barrier` Verification
Simulate high-concurrency traffic using synchronized barrier workers to prove whether an invariant holds or breaks under load:
```bash
cguard verify examples/vulnerable_wallet.py --workers 20
```

Sample exploit proof output:
```
❌ CONCURRENCY INVARIANT VIOLATED (RACE PROVEN)
Target File: examples/vulnerable_wallet.py
Target Endpoint: POST /wallet/withdraw
Concurrent Barrier Workers: 20
Initial Wallet Balance: $50
Successful Withdrawals ($50 each): 20
Final Resulting Balance: $-950

INVARIANT VIOLATION PROVEN:
Multiple concurrent withdrawals succeeded against a $50 balance due to an unlocked
Read-Modify-Write race condition (CG-001).
```

### 3. `cguard fix` — Deterministic LibCST Auto-Patcher
Inspect and apply deterministic code patches:
```bash
# Preview auto-fixes (dry-run)
cguard fix examples/vulnerable_wallet.py

# Apply specific rule fix
cguard fix examples/vulnerable_wallet.py --rule CG-001 --write

# Apply all available auto-fixes directly to disk
cguard fix examples/vulnerable_wallet.py --write
```

### 4. `cguard report` — GitHub Pull Request Markdown Reporter
Generate comprehensive Markdown summaries for CI/CD:
```bash
# Print report to stdout
cguard report examples/vulnerable_wallet.py

# Write report to markdown file for GitHub Actions PR comment
cguard report examples/vulnerable_wallet.py --output pr_report.md
```

---

## 🤖 GitHub Action Integration

Add ConcurrencyGuard to your pull request workflows:

```yaml
name: Concurrency Guard CI

on:
  pull_request:
    branches: [main]

jobs:
  concurrency-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ConcurrencyGuard Action
        uses: AyushkhatiDev/concurrency-guard@main
        with:
          path: "app"
          report-file: "app/main.py"
          output: "pr-report.md"

      - name: Post PR Comment
        if: failure() || success()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            if (fs.existsSync('pr-report.md')) {
              const body = fs.readFileSync('pr-report.md', 'utf8');
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: body
              });
            }
```

---

## 🧪 Testing

ConcurrencyGuard is thoroughly tested with unit tests and runtime stress verifications:

```bash
# Run test suite
pytest -v

# Run lint and type checking
ruff check .
mypy src/
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

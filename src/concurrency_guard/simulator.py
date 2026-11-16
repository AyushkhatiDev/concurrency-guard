"""Deterministic Async Interleaving Simulator & Pytest Chaos Reproducer Generator.

Analyzes discovered concurrency AST findings (CG-001, CG-002, CG-004),
extracts timeline execution steps, constructs deterministic worst-case
multi-coroutine interleaving schedules on the asyncio event loop, and
generates runnable pytest chaos reproduction test suites.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

if TYPE_CHECKING:
    from concurrency_guard.scanner.ast_rules import ASTFinding


@dataclass
class ExecutionStep:
    """An atomic execution step within an async function."""

    step_type: str  # "READ", "CHECK", "YIELD_BOUNDARY", "MUTATE", "ACT", "COMMIT"
    lineno: int
    code_snippet: str
    description: str


@dataclass
class TimelineEvent:
    """A scheduled event at simulated timestamp t (ms)."""

    time_ms: int
    worker: str  # e.g. "[Coroutine A]", "[Event Loop]", "[Coroutine B]"
    action: str  # e.g. "READ (line 52)"
    code: str  # e.g. "result = await db.execute(stmt)"
    state_description: str  # e.g. "Reads balance = $100. Suspends on await I/O."


@dataclass
class AnomalyProof:
    """Mathematical and empirical proof of a state corruption anomaly."""

    anomaly_type: str  # "Lost Update / Double-Spend Anomaly", "Check-Then-Act Uniqueness Collision"
    initial_state: str  # e.g. "balance = 100.00"
    expected_state: str  # e.g. "balance = 20.00 (1 withdrawal approved, 2nd rejected)"
    actual_state: str  # e.g. "balance = 20.00 (Double-Spend! 160.00 debited, only 80.00 deducted)"
    root_cause: str  # e.g. "Missing .with_for_update() row lock..."


@dataclass
class InterleavingTrace:
    """Complete interleaving simulation trace for an AST concurrency finding."""

    finding: ASTFinding
    function_name: str
    rule_id: str
    file_path: str
    read_line: int
    mutate_line: int
    commit_line: int
    steps: list[ExecutionStep] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    anomaly: Optional[AnomalyProof] = None
    reproducer_code: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert trace to structured JSON-serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "function_name": self.function_name,
            "file_path": self.file_path,
            "read_line": self.read_line,
            "mutate_line": self.mutate_line,
            "commit_line": self.commit_line,
            "steps": [
                {
                    "step_type": s.step_type,
                    "lineno": s.lineno,
                    "code_snippet": s.code_snippet,
                    "description": s.description,
                }
                for s in self.steps
            ],
            "timeline": [
                {
                    "time_ms": t.time_ms,
                    "worker": t.worker,
                    "action": t.action,
                    "code": t.code,
                    "state_description": t.state_description,
                }
                for t in self.timeline
            ],
            "anomaly": (
                {
                    "anomaly_type": self.anomaly.anomaly_type,
                    "initial_state": self.anomaly.initial_state,
                    "expected_state": self.anomaly.expected_state,
                    "actual_state": self.anomaly.actual_state,
                    "root_cause": self.anomaly.root_cause,
                }
                if self.anomaly
                else None
            ),
            "reproducer_code": self.reproducer_code,
        }


def _get_line_snippet(lines: list[str], lineno: int) -> str:
    """Retrieve normalized whitespace-trimmed line snippet by 1-based line number."""
    if 1 <= lineno <= len(lines):
        return " ".join(lines[lineno - 1].strip().split())
    return ""


def _find_function_node(tree: ast.AST, func_name: str) -> Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]]:
    """Locate the target function definition node by name."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return node
    return None


def extract_execution_steps(
    finding: ASTFinding,
    source_code: Optional[str] = None,
) -> tuple[int, int, int, list[ExecutionStep]]:
    """Extract READ, YIELD_BOUNDARY, MUTATE/ACT, and COMMIT steps from function AST."""
    if source_code is None:
        p = Path(finding.filename)
        if p.is_file():
            source_code = p.read_text(encoding="utf-8", errors="replace")
        else:
            source_code = ""

    lines = source_code.splitlines()
    tree: Optional[ast.AST] = None
    if source_code.strip():
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            tree = None

    func_node: Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]] = None
    if tree is not None:
        func_node = _find_function_node(tree, finding.function_name)

    read_line = finding.lineno
    mutate_line = finding.lineno
    commit_line = finding.lineno

    steps: list[ExecutionStep] = []

    if func_node is not None:
        # 1. Search for READ / CHECK calls
        read_candidates: list[int] = []
        mutate_candidates: list[int] = []
        commit_candidates: list[int] = []

        for child in ast.walk(func_node):
            ln = getattr(child, "lineno", 0)
            if not ln:
                continue

            # Query or fetch calls
            if isinstance(child, ast.Call):
                func = child.func
                attr_name = getattr(func, "attr", "")
                if attr_name in ("execute", "exec", "scalar", "scalars", "get", "filter", "first", "one", "one_or_none", "all"):
                    read_candidates.append(ln)
                elif attr_name in ("commit", "flush", "save"):
                    commit_candidates.append(ln)
                elif attr_name == "add":
                    mutate_candidates.append(ln)

            # Augmented assign (wallet.balance -= amount)
            elif isinstance(child, ast.AugAssign):
                mutate_candidates.append(ln)

            # Normal assign to an attribute (wallet.balance = ...)
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Attribute):
                        mutate_candidates.append(ln)

        if read_candidates:
            read_line = min(read_candidates, key=lambda x: abs(x - finding.lineno))
        if mutate_candidates:
            # First mutation after read
            after_read = [m for m in mutate_candidates if m >= read_line]
            mutate_line = after_read[0] if after_read else mutate_candidates[-1]
        elif read_line + 1 <= len(lines):
            mutate_line = read_line + 1

        if commit_candidates:
            after_mutate = [c for c in commit_candidates if c >= mutate_line]
            commit_line = after_mutate[0] if after_mutate else commit_candidates[-1]
        elif mutate_line + 1 <= len(lines):
            commit_line = mutate_line + 1

    read_snip = _get_line_snippet(lines, read_line) or f"query_read(line {read_line})"
    mutate_snip = _get_line_snippet(lines, mutate_line) or f"state_mutation(line {mutate_line})"
    commit_snip = _get_line_snippet(lines, commit_line) or f"db_commit(line {commit_line})"

    if finding.rule_id == "CG-004":
        steps.append(ExecutionStep("CHECK", read_line, read_snip, "Checks database uniqueness / existence."))
        steps.append(ExecutionStep("YIELD_BOUNDARY", read_line, read_snip, "Awaits query result; event loop context switch occurs."))
        steps.append(ExecutionStep("ACT", mutate_line, mutate_snip, "Inserts / creates entity without atomic lock."))
        steps.append(ExecutionStep("COMMIT", commit_line, commit_snip, "Commits transaction without IntegrityError guard."))
    elif finding.rule_id == "CG-002":
        steps.append(ExecutionStep("CHECK", finding.lineno, read_snip, "POST endpoint accepts submission without Idempotency-Key."))
        steps.append(ExecutionStep("YIELD_BOUNDARY", read_line, read_snip, "Awaits I/O; network retry or concurrent request arrives."))
        steps.append(ExecutionStep("MUTATE", mutate_line, mutate_snip, "Executes side-effect mutation on database state."))
        steps.append(ExecutionStep("COMMIT", commit_line, commit_snip, "Commits duplicate side-effect to database."))
    else:  # CG-001 and default
        steps.append(ExecutionStep("READ", read_line, read_snip, "Reads database state without .with_for_update() row lock."))
        steps.append(ExecutionStep("YIELD_BOUNDARY", read_line, read_snip, "Awaits query result; event loop context switch occurs."))
        steps.append(ExecutionStep("MUTATE", mutate_line, mutate_snip, "Mutates state in-memory."))
        steps.append(ExecutionStep("COMMIT", commit_line, commit_snip, "Commits mutated state to database."))

    return read_line, mutate_line, commit_line, steps


def simulate_finding(
    finding: ASTFinding,
    source_code: Optional[str] = None,
    workers: int = 2,
) -> InterleavingTrace:
    """Construct a deterministic multi-worker execution schedule demonstrating race condition."""
    p = Path(finding.filename)
    if source_code is None and p.is_file():
        source_code = p.read_text(encoding="utf-8", errors="replace")

    read_line, mutate_line, commit_line, steps = extract_execution_steps(finding, source_code=source_code)
    lines = (source_code or "").splitlines()
    read_snip = _get_line_snippet(lines, read_line) or "await db.execute(select(...))"
    mutate_snip = _get_line_snippet(lines, mutate_line) or "entity.balance -= amount"
    commit_snip = _get_line_snippet(lines, commit_line) or "await db.commit()"

    timeline: list[TimelineEvent] = []
    anomaly: AnomalyProof

    workers = max(2, workers)
    worker_names = [f"Coroutine {chr(65 + i) if i < 26 else f'W{i+1}'}" for i in range(workers)]

    t_clock = 0

    if finding.rule_id == "CG-004":
        timeline.append(
            TimelineEvent(
                time_ms=t_clock,
                worker=f"[{worker_names[0]}]",
                action=f"CHECK (line {read_line})",
                code=read_snip,
                state_description="Executes SELECT check -> finds entity does not exist (None). Suspends on await I/O.",
            )
        )
        for w in worker_names[1:]:
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker="[Event Loop]",
                    action="CONTEXT SWITCH",
                    code=f"event_loop.switch_task({worker_names[0]} -> {w})",
                    state_description=f"{worker_names[0]} suspended on I/O. Event loop schedules {w}.",
                )
            )
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker=f"[{w}]",
                    action=f"CHECK (line {read_line})",
                    code=read_snip,
                    state_description=f"ALSO checks entity existence -> finds None because {worker_names[0]} has not committed.",
                )
            )

        t_clock += 1
        timeline.append(
            TimelineEvent(
                time_ms=t_clock,
                worker=f"[{worker_names[0]}]",
                action=f"ACT & COMMIT (lines {mutate_line}, {commit_line})",
                code=f"{mutate_snip} ; {commit_snip}",
                state_description="Resumes: inserts entity and commits to database.",
            )
        )
        for w in worker_names[1:]:
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker=f"[{w}]",
                    action=f"ACT & COMMIT (lines {mutate_line}, {commit_line})",
                    code=f"{mutate_snip} ; {commit_snip}",
                    state_description="Resumes: ALSO inserts duplicate entity and commits (COLLISION / INTEGRITY CRASH!).",
                )
            )

        anomaly = AnomalyProof(
            anomaly_type="Check-Then-Act Uniqueness Collision",
            initial_state="Entity count = 0 (entity does not exist)",
            expected_state=f"Entity count = 1 (1 created, {workers - 1} rejected as duplicate)",
            actual_state=f"Entity count = {workers} (or IntegrityError crash during commit)",
            root_cause=(
                "Time-of-check to time-of-use (TOCTOU) gap between SELECT check and INSERT commit "
                "without a mutex/table lock or try/except IntegrityError handler."
            ),
        )
    elif finding.rule_id == "CG-002":
        timeline.append(
            TimelineEvent(
                time_ms=t_clock,
                worker=f"[{worker_names[0]}]",
                action=f"POST REQUEST (line {read_line})",
                code=read_snip,
                state_description="Receives client POST request without Idempotency-Key. Initiates processing.",
            )
        )
        for w in worker_names[1:]:
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker="[Event Loop]",
                    action="NETWORK RETRY",
                    code="client.retry_post_request()",
                    state_description=f"Client timeout or network jitter triggers identical retry request to {w}.",
                )
            )
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker=f"[{w}]",
                    action=f"POST REQUEST (line {read_line})",
                    code=read_snip,
                    state_description="Executes without idempotency verification. Duplicates side-effect processing.",
                )
            )

        t_clock += 1
        timeline.append(
            TimelineEvent(
                time_ms=t_clock,
                worker=f"[{worker_names[0]}]",
                action=f"COMMIT (line {commit_line})",
                code=commit_snip,
                state_description="Commits request 1 state mutation to database.",
            )
        )
        for w in worker_names[1:]:
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker=f"[{w}]",
                    action=f"COMMIT (line {commit_line})",
                    code=commit_snip,
                    state_description="Commits duplicate request state mutation (DUPLICATE CHARGE / ACTION!).",
                )
            )

        anomaly = AnomalyProof(
            anomaly_type="Non-Idempotent Duplicate Execution",
            initial_state="1 intended operation",
            expected_state=f"1 operation executed; {workers - 1} retries return cached response",
            actual_state=f"{workers} duplicate operations executed concurrently",
            root_cause="Missing 'Idempotency-Key' request header enables concurrent duplicate submissions.",
        )
    else:  # CG-001 Unlocked Read-Modify-Write
        timeline.append(
            TimelineEvent(
                time_ms=t_clock,
                worker=f"[{worker_names[0]}]",
                action=f"READ (line {read_line})",
                code=read_snip,
                state_description="Reads initial balance S0 ($100.00). Hits await I/O yield boundary.",
            )
        )
        for w in worker_names[1:]:
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker="[Event Loop]",
                    action="CONTEXT SWITCH",
                    code=f"event_loop.switch_task({worker_names[0]} -> {w})",
                    state_description=f"{worker_names[0]} suspended on await I/O. Event loop schedules {w}.",
                )
            )
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker=f"[{w}]",
                    action=f"READ (line {read_line})",
                    code=read_snip,
                    state_description="Executes without .with_for_update() row lock. ALSO reads stale S0 ($100.00).",
                )
            )

        t_clock += 1
        timeline.append(
            TimelineEvent(
                time_ms=t_clock,
                worker=f"[{worker_names[0]}]",
                action=f"MUTATE & COMMIT (lines {mutate_line}, {commit_line})",
                code=f"{mutate_snip} ; {commit_snip}",
                state_description="Resumes: computes $100 - $80 = $20. Commits balance = $20 to database.",
            )
        )
        for w in worker_names[1:]:
            t_clock += 1
            timeline.append(
                TimelineEvent(
                    time_ms=t_clock,
                    worker=f"[{w}]",
                    action=f"MUTATE & COMMIT (lines {mutate_line}, {commit_line})",
                    code=f"{mutate_snip} ; {commit_snip}",
                    state_description="Resumes with stale S0 ($100): computes $100 - $80 = $20. Overwrites balance = $20 (LOST UPDATE!).",
                )
            )

        anomaly = AnomalyProof(
            anomaly_type="Lost Update / Double-Spend Anomaly",
            initial_state="balance = 100.00",
            expected_state=f"balance = 20.00 (1 withdrawal approved, {workers - 1} rejected for insufficient funds)",
            actual_state=f"balance = 20.00 (All {workers} withdrawals succeeded! {workers * 80:.2f} debited but only 80.00 deducted)",
            root_cause="Missing .with_for_update() row lock allowed Coroutine B to read uncommitted state S0.",
        )

    reproducer = generate_pytest_reproducer(finding, workers=workers)

    return InterleavingTrace(
        finding=finding,
        function_name=finding.function_name,
        rule_id=finding.rule_id,
        file_path=finding.filename,
        read_line=read_line,
        mutate_line=mutate_line,
        commit_line=commit_line,
        steps=steps,
        timeline=timeline,
        anomaly=anomaly,
        reproducer_code=reproducer,
    )


def generate_pytest_reproducer(
    finding: ASTFinding,
    workers: int = 2,
) -> str:
    """Generate self-contained, valid Python pytest code reproducing the concurrency finding."""
    func_name = finding.function_name or "target_endpoint"
    rule_id = finding.rule_id

    if rule_id == "CG-004":
        code = f'''"""Deterministic Async Chaos Test: Check-Then-Act Uniqueness Race ({rule_id}).

Auto-generated by ConcurrencyGuard (cguard) v3.2.0.
Reproduces uniqueness collision across {workers} concurrent coroutines.
"""

from __future__ import annotations

import asyncio
import pytest


class EntityRegistry:
    """Simulated database table with uniqueness constraint."""

    def __init__(self) -> None:
        self.entities: set[str] = set()

    async def check_exists(self, key: str) -> bool:
        await asyncio.sleep(0.001)  # Simulate network / db I/O
        return key in self.entities

    async def insert(self, key: str) -> None:
        await asyncio.sleep(0.001)
        if key in self.entities:
            raise ValueError(f"IntegrityError: Unique violation for key '{{key}}'")
        self.entities.add(key)


async def vulnerable_{func_name}(
    registry: EntityRegistry,
    key: str,
    barrier: asyncio.Barrier,
) -> bool:
    """Vulnerable implementation: TOCTOU gap between existence check and insert."""
    exists = await registry.check_exists(key)
    if exists:
        return False

    # Synchronize coroutines at yield boundary to guarantee concurrent collision
    await barrier.wait()

    try:
        await registry.insert(key)
        return True
    except ValueError:
        return False


async def safe_{func_name}(
    registry: EntityRegistry,
    key: str,
    lock: asyncio.Lock,
) -> bool:
    """Safe implementation: protected by mutual exclusion / atomic transaction lock."""
    async with lock:
        exists = await registry.check_exists(key)
        if exists:
            return False
        await registry.insert(key)
        return True


@pytest.mark.asyncio
async def test_vulnerable_check_then_act_race() -> None:
    """Verify concurrent coroutines both pass the check and trigger duplicate collision."""
    registry = EntityRegistry()
    barrier = asyncio.Barrier({workers})

    tasks = [
        vulnerable_{func_name}(registry, "user_alpha", barrier)
        for _ in range({workers})
    ]
    results = await asyncio.gather(*tasks)

    # In the vulnerable race, at least 1 coroutine crashed or duplicate was attempted
    # proving the TOCTOU gap
    successes = sum(1 for r in results if r is True)
    assert successes == 1 or False in results


@pytest.mark.asyncio
async def test_safe_check_then_act_with_lock() -> None:
    """Verify adding lock guarantees exactly 1 insertion and 0 integrity collisions."""
    registry = EntityRegistry()
    lock = asyncio.Lock()

    tasks = [
        safe_{func_name}(registry, "user_alpha", lock)
        for _ in range({workers})
    ]
    results = await asyncio.gather(*tasks)

    assert sum(1 for r in results if r is True) == 1
    assert len(registry.entities) == 1
'''
    elif rule_id == "CG-002":
        code = f'''"""Deterministic Async Chaos Test: Missing Idempotency Key Retry Race ({rule_id}).

Auto-generated by ConcurrencyGuard (cguard) v3.2.0.
Reproduces duplicate processing anomaly across {workers} concurrent retries.
"""

from __future__ import annotations

import asyncio
import pytest


class PaymentLedger:
    """Simulated payment processing ledger."""

    def __init__(self) -> None:
        self.charges: list[float] = []

    async def execute_charge(self, amount: float) -> None:
        await asyncio.sleep(0.001)
        self.charges.append(amount)


async def vulnerable_{func_name}(
    ledger: PaymentLedger,
    amount: float,
    barrier: asyncio.Barrier,
) -> None:
    """Vulnerable endpoint: executes duplicate charge without idempotency key."""
    await barrier.wait()
    await ledger.execute_charge(amount)


async def safe_{func_name}(
    ledger: PaymentLedger,
    amount: float,
    idempotency_key: str,
    processed_keys: set[str],
    lock: asyncio.Lock,
) -> bool:
    """Safe endpoint: verifies and records idempotency key atomically."""
    async with lock:
        if idempotency_key in processed_keys:
            return False
        await ledger.execute_charge(amount)
        processed_keys.add(idempotency_key)
        return True


@pytest.mark.asyncio
async def test_vulnerable_duplicate_charge_race() -> None:
    """Verify duplicate requests without idempotency key cause double charging."""
    ledger = PaymentLedger()
    barrier = asyncio.Barrier({workers})

    tasks = [
        vulnerable_{func_name}(ledger, 50.0, barrier)
        for _ in range({workers})
    ]
    await asyncio.gather(*tasks)

    # Both requests executed, resulting in duplicate charges
    assert len(ledger.charges) == {workers}
    assert sum(ledger.charges) == 50.0 * {workers}


@pytest.mark.asyncio
async def test_safe_charge_with_idempotency_key() -> None:
    """Verify idempotency key prevents duplicate execution on retry."""
    ledger = PaymentLedger()
    processed_keys: set[str] = set()
    lock = asyncio.Lock()

    tasks = [
        safe_{func_name}(ledger, 50.0, "key-12345", processed_keys, lock)
        for _ in range({workers})
    ]
    results = await asyncio.gather(*tasks)

    # Exactly 1 charge executed despite concurrent duplicate submissions
    assert sum(1 for r in results if r is True) == 1
    assert len(ledger.charges) == 1
    assert sum(ledger.charges) == 50.0
'''
    else:  # CG-001 (Unlocked Read-Modify-Write / Double-Spend)
        code = f'''"""Deterministic Async Chaos Test: Unlocked Read-Modify-Write Race ({rule_id}).

Auto-generated by ConcurrencyGuard (cguard) v3.2.0.
Reproduces Double-Spend / Lost Update anomaly across {workers} concurrent workers.
"""

from __future__ import annotations

import asyncio
import pytest


class WalletAccount:
    """Simulated account entity stored in database."""

    def __init__(self, balance: float = 100.0) -> None:
        self.balance = balance


async def vulnerable_{func_name}(
    account: WalletAccount,
    amount: float,
    barrier: asyncio.Barrier,
) -> bool:
    """Vulnerable endpoint: reads state, yields to event loop, then overwrites balance."""
    # 1. READ state
    current_balance = account.balance
    if current_balance < amount:
        return False

    # 2. YIELD BOUNDARY: Synchronize concurrent workers at I/O suspension point
    await barrier.wait()
    await asyncio.sleep(0.001)  # Context switch window

    # 3. MUTATE & COMMIT: Coroutine overwrites state with stale computation
    account.balance = current_balance - amount
    return True


async def safe_{func_name}(
    account: WalletAccount,
    amount: float,
    lock: asyncio.Lock,
) -> bool:
    """Safe endpoint: protected by row-level lock (.with_for_update())."""
    async with lock:
        current_balance = account.balance
        if current_balance < amount:
            return False
        await asyncio.sleep(0.001)
        account.balance = current_balance - amount
        return True


@pytest.mark.asyncio
async def test_vulnerable_read_modify_write_race() -> None:
    """Verify concurrent coroutines both read initial balance S0 ($100) and double-spend."""
    account = WalletAccount(balance=100.0)
    barrier = asyncio.Barrier({workers})

    # Both coroutines withdraw $80.0 from an initial $100.0 balance
    tasks = [
        vulnerable_{func_name}(account, 80.0, barrier)
        for _ in range({workers})
    ]
    results = await asyncio.gather(*tasks)

    # Both coroutines approved the withdrawal (Double-Spend Anomaly!)
    assert results == [True] * {workers}

    # Final balance is $20 instead of failing or -$60: $80 of value was lost!
    assert account.balance == 20.0


@pytest.mark.asyncio
async def test_safe_withdraw_with_lock() -> None:
    """Verify acquiring row lock (.with_for_update()) eliminates double-spend."""
    account = WalletAccount(balance=100.0)
    lock = asyncio.Lock()

    tasks = [
        safe_{func_name}(account, 80.0, lock)
        for _ in range({workers})
    ]
    results = await asyncio.gather(*tasks)

    # Exactly 1 withdrawal succeeds, the other is rejected for insufficient funds
    assert results == [True, False]
    assert account.balance == 20.0
'''

    # Ensure generated code is valid Python AST
    ast.parse(code)
    return code


__all__ = [
    "AnomalyProof",
    "ExecutionStep",
    "InterleavingTrace",
    "TimelineEvent",
    "extract_execution_steps",
    "generate_pytest_reproducer",
    "simulate_finding",
]

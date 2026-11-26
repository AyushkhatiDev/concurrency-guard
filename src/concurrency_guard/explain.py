"""Short code examples for the built-in rule reference."""
from __future__ import annotations

from concurrency_guard.report import AUTO_FIXABLE_RULES
from concurrency_guard.sarif import RULE_REGISTRY

# Snippets assume the enclosing application supplies the named clients and helpers.
EXAMPLES = {
    "CG-001": ("row = await db.get(Account, key)", "row = await db.get(Account, key, with_for_update=True)"),
    "CG-002": ("await charge(order)", "await charge(order, idempotency_key=order.id)"),
    "CG-003": ("rows = [await db.get(Item, key) for key in keys]", "rows = await db.scalars(select(Item).where(Item.id.in_(keys)))"),
    "CG-004": ("if not exists(key): insert(key)", "insert_on_conflict_do_nothing(key)  # unique constraint on key"),
    "CG-005": ("charge(order)", "charge(order, idempotency_key=order.id)"),
    "CG-006": ("value = counts[key]\nawait work()\ncounts[key] = value + 1", "await work()\nasync with lock:\n    counts[key] += 1"),
    "CG-007": ("shared.extend(batch)", "with lock:\n    shared.extend(batch)"),
    "CG-008": ("counts[key] += 1", "with lock:\n    counts[key] += 1"),
    "CG-009": ("path.write_text(content)", "atomic_write_text(path, content)"),
    "CG-010": ("open('/tmp/job.tmp', 'w')", "tempfile.NamedTemporaryFile()"),
    "CG-011": ("if not r.exists(key): r.set(key, value)", "r.set(key, value, nx=True)"),
    "CG-012": ("cache.delete(key)\ndb.commit()", "transaction.on_commit(lambda: cache.delete(key))"),
    "CG-013": ("with lock_b, lock_a: update()", "with lock_a, lock_b: update()  # same order in every thread"),
    "CG-014": ("worker.update_shared()", "with shared_lock:\n    worker.update_shared()"),
    "CG-015": ("alias = shared\nalias[key] += 1", "with lock:\n    shared[key] += 1"),
    "CG-016": ("row = Item.objects.get(pk=key)", "with transaction.atomic():\n    row = Item.objects.select_for_update().get(pk=key)\n    update(row)"),
    "CG-017": ("row.count += 1\nrow.save()", "Item.objects.filter(pk=key).update(count=F('count') + 1)"),
    "CG-018": ("r.delete(lock_key)", "lock.release()  # client atomically verifies ownership"),
    "CG-019": ("tasks.add_task(work, request_session)", "tasks.add_task(work_with_own_session, item_id)"),
    "CG-020": ("async with lock:\n    data = await fetch()", "data = await fetch()\nasync with lock:\n    apply(data)"),
    "CG-021": ("with lock:\n    yield shared[key]", "with lock:\n    value = shared[key]\nyield value"),
    "CG-022": ("notify.delay(pk)\ntransaction.commit()", "transaction.on_commit(lambda: notify.delay(pk))"),
    "CG-023": ("send_payment(amount)", "send_payment(amount, idempotency_key=job.id)"),
    "CG-024": ("async with db.begin():\n    data = await fetch()", "data = await fetch()\nasync with db.begin():\n    db.add(Row(data=data))"),
    "CG-025": ("time.sleep(1)", "await asyncio.sleep(1)"),
    "CG-026": ("asyncio.create_task(work())", "async with asyncio.TaskGroup() as group:\n    group.create_task(work())"),
    "CG-027": ("if not r.get(key): r.set(key, value)", "r.set(key, value, nx=True)"),
    "CG-028": ("if flag: lock_row()\nmutate_row()", "lock_row()\nmutate_row()"),
    "CG-029": ("with second, first: update()", "with first, second: update()  # project-wide order"),
    "CG-030": ("before = shared[key]\nawait work()\nshared[key] = before + 1", "await work()\nasync with lock:\n    shared[key] += 1"),
    "CG-031": ("await asyncio.gather(load(db), save(db))", "async with factory() as reader, factory() as writer:\n    await asyncio.gather(load(reader), save(writer))"),
    "CG-032": ("async with lock:\n    async with lock: update()", "async with lock:\n    update()"),
    "CG-033": ("try: await work()\nexcept asyncio.CancelledError: pass", "try: await work()\nexcept asyncio.CancelledError:\n    await cleanup()\n    raise"),
}

IMPACT = {
    "CG-028": "A branch can reach a write without locking the row, losing another transaction's update.",
    "CG-029": "Workers acquiring the same pair in opposite orders can wait forever.",
    "CG-030": "Another coroutine can change the value while this task is suspended.",
    "CG-031": "An AsyncSession owns mutable transaction state. Overlapping operations can interrupt a flush or commit.",
    "CG-032": "The task waits for a lock that only it can release.",
    "CG-033": "A task can continue after cancellation, delaying shutdown or a TaskGroup exit.",
}


def explain_rule(rule_id: str) -> str:
    meta = RULE_REGISTRY[rule_id]
    unsafe, safe = EXAMPLES[rule_id]
    cwes = ", ".join(tag.upper() for tag in meta["properties"]["tags"] if tag.startswith("cwe-"))
    fix = "available for eligible sites" if rule_id in AUTO_FIXABLE_RULES else "manual"
    why = IMPACT.get(rule_id, meta["fullDescription"]["text"])
    return (f"{rule_id}  {meta['shortDescription']['text']}  {cwes}\n\n{why}\n\n"
            f"Unsafe example\n{unsafe}\n\nSafe example\n{safe}\n\nAutofix: {fix}")

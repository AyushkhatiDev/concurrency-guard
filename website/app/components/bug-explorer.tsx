"use client";

import { Copy, RotateCcw } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { useState } from "react";
import { recordedWalletScan } from "../lib/evidence";

type Example = { name: string; rule: string; finding: string; unsafe: string[]; patched: string[]; hot: number[] };
const examples: Example[] = [
  { name: "Django", rule: "CG-016", finding: "wallet.py:12 · Django unlocked read-modify-write", unsafe: ["def deduct(user_id, amount):", "    wallet = Wallet.objects.get(id=user_id)", "    if wallet.balance < amount:", "        raise InsufficientFunds()", "    wallet.balance -= amount", "    wallet.save()"], patched: ["@transaction.atomic", "def deduct(user_id, amount):", "    wallet = Wallet.objects.select_for_update().get(id=user_id)", "    if wallet.balance < amount:", "        raise InsufficientFunds()", "    wallet.balance -= amount", "    wallet.save()"], hot: [2, 5, 6] },
  { name: "FastAPI", rule: "CG-001", finding: "routers/wallet.py:28 · unlocked SQLAlchemy mutation", unsafe: ["async def withdraw(request, db):", "    wallet = await db.get(Wallet, request.id)", "    if wallet.balance < request.amount:", "        raise HTTPException(400)", "    wallet.balance -= request.amount", "    await db.commit()"], patched: ["async def withdraw(request, db):", "    wallet = await db.scalar(", "        select(Wallet).where(Wallet.id == request.id).with_for_update()", "    )", "    wallet.balance -= request.amount", "    await db.commit()"], hot: [2, 5, 6] },
  { name: "Celery", rule: "CG-005", finding: "tasks/charge.py:9 · non-idempotent retry", unsafe: ["@app.task(bind=True)", "def charge(self, order_id):", "    order = Order.objects.get(id=order_id)", "    gateway.charge(order.total)", "    order.status = 'paid'", "    order.save()"], patched: ["@app.task(bind=True, acks_late=True)", "def charge(self, order_id):", "    with idempotency_lock(order_id):", "        order = Order.objects.select_for_update().get(id=order_id)", "        gateway.charge(order.total)", "        order.status = 'paid'"], hot: [3, 4, 5] },
  { name: "SQLAlchemy", rule: "CG-004", finding: "services/users.py:41 · check-then-act uniqueness race", unsafe: ["existing = db.scalar(select(User).where(User.email == email))", "if not existing:", "    db.add(User(email=email))", "    db.commit()"], patched: ["try:", "    db.add(User(email=email))", "    db.commit()", "except IntegrityError:", "    db.rollback()"], hot: [1, 2, 3] },
  { name: "asyncio", rule: "CG-006", finding: "workers/cache.py:16 · shared collection mutation", unsafe: ["async def push(value):", "    if value not in cache:", "        await asyncio.sleep(0)", "        cache.append(value)"], patched: ["cache_lock = asyncio.Lock()", "async def push(value):", "    async with cache_lock:", "        if value not in cache:", "            cache.append(value)"], hot: [2, 4] },
];

export function BugExplorer() {
  const [selected, setSelected] = useState(0);
  const [patched, setPatched] = useState(false);
  const [hovered, setHovered] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);
  const reduceMotion = useReducedMotion();
  const example = examples[selected];
  const lines = patched ? example.patched : example.unsafe;
  const windowLines = [example.hot[0], example.hot.at(-1) ?? example.hot[0]];

  async function copyTranscript() {
    await navigator.clipboard.writeText(`${recordedWalletScan.command}\n${recordedWalletScan.findingsCount} findings · ${recordedWalletScan.scannedFiles} file · ${recordedWalletScan.elapsedMs} ms`);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return <section id="examples" className="section bug-section" aria-labelledby="bug-heading">
    <div className="section-marker">01 / DETECT</div>
    <div className="section-heading"><h2 id="bug-heading">The bug, line by line.</h2><p>cguard follows the read, the check, and the write — even when they are separated by application code.</p></div>
    <div className="example-tabs" role="tablist" aria-label="Framework examples">{examples.map((item, index) => <button type="button" role="tab" aria-selected={selected === index} key={item.name} onClick={() => { setSelected(index); setPatched(false); }}>{item.name}</button>)}</div>
    <div className="bug-grid">
      <motion.div key={`${example.name}-${patched}`} initial={reduceMotion ? false : { opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="code-paper">
        <div className="code-header"><span>{example.rule} / {patched ? "PATCHED" : "VULNERABLE"}</span><button type="button" onClick={() => setPatched((value) => !value)} aria-pressed={patched}>{patched ? "Show finding" : "Show patch"}</button></div>
        <div className="code-body">
          <span className="race-window" style={{ top: `${19 + (windowLines[0] - 1) * 22.2}px`, height: `${(windowLines[1] - windowLines[0] + 1) * 22.2}px` }}><b>race window</b></span>
          <pre>{lines.map((line, index) => <code key={`${line}-${index}`} onMouseEnter={() => setHovered(index + 1)} onMouseLeave={() => setHovered(null)} className={`${!patched && example.hot.includes(index + 1) ? "unsafe-line" : ""} ${patched && (index < 3 || line.includes("select_for_update") || line.includes("Lock") || line.includes("IntegrityError")) ? "safe-line" : ""} ${hovered === index + 1 ? "line-active" : ""}`}><span>{String(index + 1).padStart(2, "0")}</span>{line || " "}{patched && index === 0 && <em className="preserved-tag">preserved</em>}</code>)}</pre>
        </div>
      </motion.div>
      <aside className="terminal-paper" aria-label="Recorded cguard scan transcript">
        <div className="terminal-title"><span>RECORDED SCAN / cguard {recordedWalletScan.packageVersion}</span><span>{recordedWalletScan.capturedAt}</span></div>
        <pre><span className="terminal-prompt">$ </span>{recordedWalletScan.command}{`\n\n`}<span className="danger-text">{recordedWalletScan.findings[0].ruleId}</span>  examples/vulnerable_wallet.py:{recordedWalletScan.findings[0].line}{`\n`}      function: {recordedWalletScan.findings[0].functionName}{`\n`}<span className="danger-text">{recordedWalletScan.findings[1].ruleId}</span>  examples/vulnerable_wallet.py:{recordedWalletScan.findings[1].line}{`\n`}      function: {recordedWalletScan.findings[1].functionName}{`\n\n`}<span className="safe-text">✓ JSON transcript captured locally</span></pre>
        <dl className="scan-metrics"><div><dt>files</dt><dd>{recordedWalletScan.scannedFiles}</dd></div><div><dt>findings</dt><dd>{recordedWalletScan.findingsCount}</dd></div><div><dt>elapsed</dt><dd>{recordedWalletScan.elapsedMs} ms</dd></div></dl>
        <div className="terminal-foot"><span>REAL RECORDED OUTPUT</span><button type="button" onClick={copyTranscript}>{copied ? <RotateCcw /> : <Copy />}{copied ? "Copied" : "Copy"}</button></div>
      </aside>
    </div>
  </section>;
}

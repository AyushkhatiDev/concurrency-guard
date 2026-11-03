"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Braces, CheckCircle2, Code2 } from "lucide-react";
import { useState } from "react";

type Demo = { id: "django" | "fastapi"; label: string; rule: string; unsafe: string[]; safe: string[]; redLine: number; greenLine: number };

const demos: Demo[] = [
  {
    id: "django", label: "Django", rule: "CG-016 · Django ORM unlocked RMW",
    unsafe: ["from django.db import transaction", "", "def deduct(request, user_id, amount):", "    wallet = Wallet.objects.get(user_id=user_id)", "    if wallet.balance < amount:", "        raise InsufficientFunds()", "", "    wallet.balance -= amount", "    wallet.save()"],
    safe: ["from django.db import transaction", "", "@transaction.atomic", "def deduct(request, user_id, amount):", "    wallet = Wallet.objects.select_for_update().get(", "        user_id=user_id", "    )", "    if wallet.balance < amount:", "        raise InsufficientFunds()", "", "    wallet.balance -= amount", "    wallet.save()"],
    redLine: 4, greenLine: 5,
  },
  {
    id: "fastapi", label: "FastAPI", rule: "CG-001 · SQLAlchemy unlocked RMW",
    unsafe: ["@app.post(\"/wallet/withdraw\")", "async def withdraw(request, db):", "    stmt = select(Wallet).where(", "        Wallet.user_id == request.user_id", "    )", "    wallet = (await db.execute(stmt)).scalar_one()", "", "    wallet.balance -= request.amount", "    await db.commit()"],
    safe: ["@app.post(\"/wallet/withdraw\")", "async def withdraw(request, db):", "    stmt = select(Wallet).where(", "        Wallet.user_id == request.user_id", "    ).with_for_update()", "    wallet = (await db.execute(stmt)).scalar_one()", "", "    wallet.balance -= request.amount", "    await db.commit()"],
    redLine: 8, greenLine: 5,
  },
];

function CodePane({ title, lines, emphasis, safe }: { title: string; lines: string[]; emphasis: number; safe?: boolean }) {
  return <div className="min-w-0 border-white/10 bg-[#080808] p-4 sm:p-5">
    <div className="mb-4 flex items-center gap-2 text-xs font-medium tracking-wide text-zinc-400"><Code2 className="size-3.5" />{title}</div>
    <pre className="code-scroll overflow-x-auto font-mono text-[11px] leading-6 text-zinc-300 sm:text-xs" aria-label={`${title} code sample`}>
      {lines.map((line, index) => <code key={`${line}-${index}`} className={`block min-w-max rounded px-2 ${index + 1 === emphasis ? safe ? "bg-emerald-500/10 text-emerald-200 ring-1 ring-emerald-400/20" : "bg-rose-500/10 text-rose-200 ring-1 ring-rose-400/20" : ""}`}>
        <span className="mr-4 inline-block w-4 select-none text-right text-zinc-600">{index + 1}</span>{line || " "}
      </code>)}
    </pre>
  </div>;
}

export function CodeShowcase() {
  const [selected, setSelected] = useState<Demo["id"]>("django");
  const reduceMotion = useReducedMotion();
  const demo = demos.find((item) => item.id === selected) ?? demos[0];

  return <section aria-labelledby="demo-heading" className="mx-auto max-w-6xl px-5 pb-28 sm:px-8">
    <motion.div initial={reduceMotion ? false : { opacity: 0, y: 18 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, amount: 0.2 }} transition={{ duration: 0.45 }} className="overflow-hidden rounded-2xl border border-white/10 bg-[#090909] shadow-2xl shadow-black/50">
      <div className="flex flex-col gap-4 border-b border-white/10 bg-white/[0.02] px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <div className="flex items-center gap-2"><span className="size-2.5 rounded-full bg-rose-400/80" /><span className="size-2.5 rounded-full bg-amber-300/80" /><span className="size-2.5 rounded-full bg-emerald-400/80" /><span className="ml-2 font-mono text-xs text-zinc-500">cguard fix --write</span></div>
        <div role="tablist" aria-label="Code examples" className="flex w-fit rounded-lg border border-white/10 bg-black/30 p-1">
          {demos.map((item) => <button key={item.id} role="tab" aria-selected={selected === item.id} onClick={() => setSelected(item.id)} className={`rounded-md px-3 py-1.5 text-xs transition ${selected === item.id ? "bg-white/10 text-white" : "text-zinc-500 hover:text-zinc-200"}`}>{item.label}</button>)}
        </div>
      </div>
      <div className="border-b border-white/10 px-5 py-4 sm:px-6"><p className="text-xs font-medium uppercase tracking-[0.16em] text-sky-300">Auto-remediation preview</p><h2 id="demo-heading" className="mt-1 text-lg font-medium text-white">{demo.rule}</h2></div>
      <AnimatePresence mode="wait">
        <motion.div key={demo.id} initial={reduceMotion ? false : { opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={reduceMotion ? undefined : { opacity: 0, x: -10 }} transition={{ duration: 0.2 }} className="grid divide-y divide-white/10 md:grid-cols-2 md:divide-x md:divide-y-0">
          <CodePane title="Vulnerable" lines={demo.unsafe} emphasis={demo.redLine} />
          <CodePane title="Patched by cguard" lines={demo.safe} emphasis={demo.greenLine} safe />
        </motion.div>
      </AnimatePresence>
      <div className="flex items-center gap-2 border-t border-white/10 bg-emerald-400/[0.04] px-5 py-3 text-xs text-emerald-200"><CheckCircle2 className="size-4" />Lossless LibCST patch preserves formatting and comments.</div>
    </motion.div>
  </section>;
}

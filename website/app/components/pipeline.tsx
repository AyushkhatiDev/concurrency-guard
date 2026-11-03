"use client";

import { motion, useReducedMotion } from "framer-motion";

const steps = [
  { no: "02.1", title: "Trace the call path", copy: "A route can delegate a mutation three files away. The call graph keeps the connection intact.", visual: <div className="graph-visual"><i>routes.py</i><span>→</span><i>service.py</i><span>→</span><b>cache.py / mutate()</b></div> },
  { no: "02.2", title: "Follow shared state", copy: "Taint tracking follows a mutable reference through aliases, arguments, and attribute access.", visual: <div className="taint-visual"><span>global_cache</span><em>↘ alias ↘ argument</em><b>items.append()</b></div> },
  { no: "02.3", title: "Force the interleaving", copy: "The runtime verifier releases workers at a barrier, then compares the observed state with the invariant.", visual: <div className="barrier-visual"><span>worker 01</span><span>worker 02</span><span>worker 03</span><b>BARRIER</b><em>14 / 50 increments observed</em></div> },
  { no: "02.4", title: "Patch without reformatting", copy: "LibCST makes a narrow source edit and preserves the comments and layout already in your file.", visual: <div className="patch-visual"><code># keep this audit note</code><del>Wallet.objects.get(...)</del><ins>Wallet.objects.select_for_update().get(...)</ins></div> },
];

export function Pipeline() { const reduceMotion = useReducedMotion(); return <section className="section pipeline-section" aria-labelledby="how-heading"><div className="section-marker">02 / TRACE</div><div className="section-heading"><h2 id="how-heading">One path from finding to fix.</h2><p>Every stage leaves evidence you can inspect locally.</p></div><div className="pipeline-list">{steps.map((step, index) => <motion.article key={step.no} initial={reduceMotion ? false : { opacity: 0, y: 18 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, amount: .35 }} transition={{ duration: .45, delay: index * .07 }} className="pipeline-step"><div className="step-copy"><span>{step.no}</span><h3>{step.title}</h3><p>{step.copy}</p></div><div className="step-visual">{step.visual}</div></motion.article>)}</div></section>; }

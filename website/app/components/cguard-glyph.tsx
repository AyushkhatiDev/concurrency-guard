"use client";

import { motion, useInView, useReducedMotion } from "framer-motion";
import { useEffect, useRef, useState } from "react";

export function CguardGlyph() {
  const ref = useRef<SVGSVGElement>(null);
  const visible = useInView(ref, { once: true, amount: 0.35 });
  const reduceMotion = useReducedMotion();
  const [locked, setLocked] = useState(reduceMotion);

  useEffect(() => {
    if (!visible || reduceMotion || locked) return;
    let timer: number | undefined;
    function advance() {
      if (!document.hidden) timer = window.setTimeout(() => setLocked(true), 980);
    }
    function onVisibilityChange() {
      if (!document.hidden && !timer) advance();
    }
    advance();
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => { if (timer) window.clearTimeout(timer); document.removeEventListener("visibilitychange", onVisibilityChange); };
  }, [locked, reduceMotion, visible]);

  const laneColor = locked ? "var(--safe)" : "var(--danger)";
  return <svg ref={ref} className="cguard-glyph" viewBox="0 0 620 390" aria-hidden="true" focusable="false">
    <motion.path d="M74 102H178L234 171M178 102L234 298" fill="none" stroke="var(--rule)" strokeWidth="1.5" initial={{ pathLength: 0, opacity: 0 }} animate={{ pathLength: visible || reduceMotion ? 1 : 0, opacity: 1 }} transition={{ duration: .48, ease: [0.22, 1, 0.36, 1] }} />
    <motion.path d="M249 171H364C398 171 410 216 440 238" fill="none" stroke={laneColor} strokeWidth="2" strokeDasharray="6 7" initial={{ pathLength: 0, opacity: 0 }} animate={{ pathLength: visible || reduceMotion ? 1 : 0, opacity: 1 }} transition={{ duration: .48, delay: .16, ease: [0.22, 1, 0.36, 1] }} />
    <motion.path d="M249 298H364C398 298 410 260 440 238" fill="none" stroke={laneColor} strokeWidth="2" strokeDasharray="6 7" initial={{ pathLength: 0, opacity: 0 }} animate={{ pathLength: visible || reduceMotion ? 1 : 0, opacity: 1 }} transition={{ duration: .48, delay: .28, ease: [0.22, 1, 0.36, 1] }} />
    <motion.path d="M456 238H546" fill="none" stroke="var(--rule)" strokeWidth="1.5" initial={{ pathLength: 0 }} animate={{ pathLength: visible || reduceMotion ? 1 : 0 }} transition={{ duration: .32, delay: .68 }} />

    <motion.g initial={{ opacity: 0, y: 8 }} animate={{ opacity: visible || reduceMotion ? 1 : 0, y: 0 }} transition={{ duration: .36, delay: .05 }}>
      <rect x="34" y="67" width="82" height="70" fill="var(--paper)" stroke="var(--ink)" strokeWidth="1.5" />
      <path d="M91 67V92H116" fill="none" stroke="var(--ink)" strokeWidth="1.5" />
      <path d="M52 109H97M52 119H83" fill="none" stroke="var(--ink)" strokeWidth="1.5" />
    </motion.g>
    <motion.g initial={{ opacity: 0, scale: .88 }} animate={{ opacity: visible || reduceMotion ? 1 : 0, scale: 1 }} transition={{ duration: .3, delay: .42 }}>
      <circle cx="242" cy="171" r="10" fill="var(--paper)" stroke="var(--ink)" strokeWidth="1.5" />
      <circle cx="242" cy="298" r="10" fill="var(--paper)" stroke="var(--ink)" strokeWidth="1.5" />
    </motion.g>
    <motion.g animate={{ scale: locked ? 1 : [1, 1.12, 1], opacity: visible || reduceMotion ? 1 : 0 }} transition={locked ? { duration: .24 } : { duration: .76, repeat: 1, ease: "easeInOut" }} style={{ transformOrigin: "448px 238px" }}>
      <circle cx="448" cy="238" r="16" fill="var(--paper)" stroke={laneColor} strokeWidth="2" />
      <path d="M441 238H455M448 231V245" stroke={laneColor} strokeWidth="2" />
    </motion.g>
    <motion.g initial={{ opacity: 0 }} animate={{ opacity: locked ? 1 : 0 }} transition={{ duration: .22 }}>
      <rect x="535" y="218" width="23" height="22" rx="1" fill="var(--paper)" stroke="var(--safe)" strokeWidth="2" />
      <path d="M541 218V211C541 202 552 202 552 211V218" fill="none" stroke="var(--safe)" strokeWidth="2" />
    </motion.g>
  </svg>;
}

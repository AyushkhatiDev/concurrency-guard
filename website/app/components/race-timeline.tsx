"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Pause, Play, RotateCcw, StepForward } from "lucide-react";
import { useEffect, useState } from "react";

const steps = [
  "Both requests read the same balance.",
  "Both checks pass against the same stale value.",
  "Both writes land; the second withdrawal is lost.",
  "cguard adds a row lock before either mutation.",
  "Requests serialize and the balance remains correct.",
];

export function RaceTimeline() {
  const reduceMotion = useReducedMotion();
  const [step, setStep] = useState(reduceMotion ? 4 : 0);
  const [playing, setPlaying] = useState(!reduceMotion);
  const safe = step >= 3;

  useEffect(() => {
    if (!playing || reduceMotion) return;
    const timer = window.setInterval(() => setStep((current) => (current >= 4 ? 0 : current + 1)), 2000);
    return () => window.clearInterval(timer);
  }, [playing, reduceMotion]);

  function next() {
    setPlaying(false);
    setStep((current) => (current >= 4 ? 0 : current + 1));
  }

  return <section className="timeline" aria-label="Illustrative double-spend race timeline">
    <div className="timeline-head">
      <span className="eyebrow">ILLUSTRATIVE SIMULATION / CG-016</span>
      <span className={safe ? "signal-safe" : "signal-danger"}>{safe ? "● VERIFIED PATH" : "× RACE PATH"}</span>
    </div>
    <div className="timeline-readout">
      <span>wallet.balance</span>
      <strong className={safe ? "signal-safe" : "signal-danger"}>{safe ? "0" : step === 2 ? "50 (stale)" : "100"}</strong>
      <small>{safe ? "serialized result" : "starting balance"}</small>
    </div>
    <div className="timeline-lanes">
      {["Request A", "Request B"].map((lane, laneIndex) => <div className="lane" key={lane}>
        <div className="lane-label"><b>{lane}</b><span>thr-{laneIndex + 17}</span></div>
        <div className="lane-content">
          <div className="lane-lock-row" aria-hidden={!safe}>
            {safe && <motion.span className="lock-bar" initial={reduceMotion ? false : { scaleX: 0 }} animate={{ scaleX: 1 }}>select_for_update()</motion.span>}
          </div>
          <div className="lane-chip-row">
            {!safe && <>
              <motion.span className="event read" initial={reduceMotion ? false : { opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}>get() → 100</motion.span>
              {step >= 1 && <motion.span className="event check" initial={reduceMotion ? false : { opacity: 0 }} animate={{ opacity: 1 }}>check ✓</motion.span>}
              {step >= 2 && <motion.span className="event write danger" initial={reduceMotion ? false : { opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>write 50</motion.span>}
            </>}
            {safe && <>
              <motion.span className="event read" initial={reduceMotion ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: laneIndex * .25 }}>get() → {laneIndex ? "50" : "100"}</motion.span>
              {laneIndex === 1 && <span className="wait">waits for lock</span>}
              <motion.span className="event write safe" initial={reduceMotion ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .35 + laneIndex * .25 }}>write {laneIndex ? "0" : "50"}</motion.span>
            </>}
          </div>
        </div>
      </div>)}
      <div className="collision-row" aria-live="polite">
        <AnimatePresence>{!safe && step >= 2 && <motion.span className="collision" initial={reduceMotion ? false : { opacity: 0, scale: .9 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}>× DOUBLE SPEND</motion.span>}</AnimatePresence>
      </div>
    </div>
    <div className="timeline-caption"><span>{String(step + 1).padStart(2, "0")} / 05</span><p>{steps[step]}</p></div>
    <div className="timeline-controls">
      <button type="button" onClick={() => setPlaying((value) => !value)} aria-label={playing ? "Pause timeline" : "Play timeline"}>{playing ? <Pause /> : <Play />}{playing ? "Pause" : "Play"}</button>
      <button type="button" onClick={next}><StepForward />Step through</button>
      <button type="button" onClick={() => { setPlaying(false); setStep(0); }}><RotateCcw />Reset</button>
    </div>
  </section>;
}

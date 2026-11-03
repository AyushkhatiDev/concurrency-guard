"use client";

import { ArrowUpRight, Check, Copy, Moon, Sun } from "lucide-react";
import { motion, useScroll, useSpring } from "framer-motion";
import { useState } from "react";
import type { CSSProperties, FormEvent } from "react";
import { BugExplorer } from "./components/bug-explorer";
import { Pipeline } from "./components/pipeline";
import { RaceTimeline } from "./components/race-timeline";
import { RuleCatalog } from "./components/rule-catalog";
import { CguardGlyph } from "./components/cguard-glyph";
import { numericClaims } from "./lib/evidence";

const github = "https://github.com/AyushkhatiDev/concurrency-guard";
const pypi = "https://pypi.org/project/concurrency-guard/";

function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() { await navigator.clipboard.writeText(command); setCopied(true); window.setTimeout(() => setCopied(false), 1700); }
  return <button type="button" className="command-button" onClick={copy}><code>$ {command}</code>{copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}<span className="sr-only">Copy command</span></button>;
}

function Waitlist() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "success" | "error" | "loading">("idle");
  const [message, setMessage] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!/^\S+@\S+\.\S+$/.test(email)) { setState("error"); setMessage("Enter a valid email address."); return; }
    const endpoint = process.env.NEXT_PUBLIC_FORMSPREE_ENDPOINT;
    if (!endpoint) { setState("error"); setMessage("Waitlist endpoint is not configured yet."); return; }
    setState("loading"); setMessage("");
    try {
      const response = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ email }) });
      if (!response.ok) throw new Error();
      setState("success"); setMessage("You’re on the list."); setEmail("");
    } catch { setState("error"); setMessage("Could not submit right now. Please try again."); }
  }
  return <section id="waitlist" className="waitlist" aria-labelledby="waitlist-heading">
    <div>
      <span className="section-marker">06 / GITHUB APP</span>
      <h2 id="waitlist-heading">Put the finding on the pull request.</h2>
      <p>Early access for a GitHub App that turns a detected race into a reviewable patch.</p>
      <form className={`waitlist-form is-${state}`} onSubmit={submit} noValidate>
        <label className="sr-only" htmlFor="email">Email address</label>
        <input id="email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" aria-invalid={state === "error"} aria-describedby="waitlist-message" disabled={state === "loading"} />
        <button disabled={state === "loading"}>{state === "loading" ? "Joining…" : "Join waitlist"} <ArrowUpRight /></button>
      </form>
      <p id="waitlist-message" className={`form-message ${state === "error" ? "danger-text" : state === "success" ? "safe-text" : ""}`} role={state === "error" ? "alert" : "status"} aria-live="polite">{message || "No marketing drip. Just product access."}</p>
    </div>
    <aside className="pr-comment"><div><span className="bot-dot">c</span><b>cguard bot</b><small>commented now</small></div><p><strong>CG-016</strong> unlocked Django mutation in <code>wallet.py:12</code></p><pre><del>Wallet.objects.get(id=user_id)</del>{`\n`}<ins>Wallet.objects.select_for_update().get(id=user_id)</ins></pre><button type="button">Apply suggested fix</button></aside>
  </section>;
}

export default function Home() {
  const { scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 28, restDelta: .001 });
  const [dark, setDark] = useState(false);
  const theme = (dark ? { "--paper": "#0E0F0C", "--ink": "#F4F1EA", "--muted": "#b8b1a5", "--rule": "#403f39", "--danger": "#ff6540", "--safe": "#42ad79" } : { "--paper": "#F4F1EA", "--ink": "#12110F", "--muted": "#5B574F", "--rule": "#D9D4C7", "--danger": "#FF4D1C", "--safe": "#1F7A4D" }) as CSSProperties;
  const claims = numericClaims.filter((claim) => ["Documented rules", "Network calls required"].includes(claim.label));
  return <main className={dark ? "theme-dark" : "theme-light"} style={{ ...theme, background: "var(--paper)", color: "var(--ink)" }}>
    <motion.div className="progress" style={{ scaleX: progress }} />
    <nav><a className="wordmark" href="#top">cguard<span> / </span>race inspector</a><div><a href="#examples">Examples</a><a href="#catalog">Rules</a><a href={github} target="_blank" rel="noreferrer">GitHub ↗</a><button type="button" className="theme-toggle" onClick={() => setDark((value) => !value)} aria-label={dark ? "Use light theme" : "Use dark theme"}>{dark ? <Sun /> : <Moon />}</button></div></nav>
    <section className="hero" id="top"><div className="hero-rail"><div className="hero-copy"><span className="section-marker">00 / CONCURRENCY INSPECTOR</span><h1>Your code has a race condition.<br /><em>Watch it happen.</em></h1><p>Find read-modify-write races, reproduce them under pressure, and patch them without touching your formatting.</p><div className="hero-actions"><CopyCommand command="pip install concurrency-guard" /><a className="text-link" href="#waitlist">Join GitHub App waitlist <ArrowUpRight /></a></div></div><figure className="hero-glyph-figure"><CguardGlyph /><figcaption><span>source</span><span>threads</span><span>lock</span></figcaption></figure><div className="hero-note"><span>LOCAL-ONLY ANALYSIS</span><span>MIT LICENSE</span><span>PYTHON 3.9+</span></div></div><RaceTimeline /></section>
    <BugExplorer />
    <Pipeline />
    <section className="section proof" aria-labelledby="proof-heading"><div className="section-marker">03 / COVERAGE</div><div className="section-heading"><h2 id="proof-heading">Specific checks, named plainly.</h2><p>Every displayed number has a source. Modeled timeline outcomes are labeled as simulations.</p></div><dl>{claims.map((claim) => <div key={claim.label}><dt>{claim.value}</dt><dd>{claim.label.toLowerCase()}<br /><small>{claim.source} · {claim.capturedAt}</small></dd></div>)}<div><dt>8</dt><dd>analysis surfaces<br />ORM, async, threads, files, cache, locks, tasks, Python</dd></div></dl></section>
    <RuleCatalog />
    <section className="section run" aria-labelledby="run-heading"><div className="section-marker">05 / RUN LOCALLY</div><div className="section-heading"><h2 id="run-heading">No account. No upload. No detour.</h2><p>Install the CLI, scan a path, and review the source-preserving patch on your own machine.</p></div><div className="terminal-run"><ol><li><span>01</span><CopyCommand command="pip install concurrency-guard" /></li><li><span>02</span><CopyCommand command="cguard scan app/" /></li><li><span>03</span><CopyCommand command="cguard fix app/wallet.py --write" /></li></ol><p><b>PRIVACY /</b> Nothing leaves your machine. cguard parses source with Python AST and LibCST locally.</p></div></section>
    <Waitlist />
    <footer><span>© 2026 cguard / MIT</span><div><a href={github} target="_blank" rel="noreferrer">GitHub</a><a href={pypi} target="_blank" rel="noreferrer">PyPI</a><a href="https://github.com/AyushkhatiDev/concurrency-guard/blob/main/README.md" target="_blank" rel="noreferrer">Docs</a><a href="https://opensource.org/licenses/MIT" target="_blank" rel="noreferrer">License</a></div></footer>
  </main>;
}

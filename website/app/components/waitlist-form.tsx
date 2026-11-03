"use client";

import { ArrowRight, LoaderCircle } from "lucide-react";
import { FormEvent, useState } from "react";

type Status = "idle" | "loading" | "success" | "error";

export function WaitlistForm() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedEmail = email.trim();
    if (!/^\S+@\S+\.\S+$/.test(normalizedEmail)) { setStatus("error"); setMessage("Enter a valid email address."); return; }
    const endpoint = process.env.NEXT_PUBLIC_FORMSPREE_ENDPOINT;
    if (!endpoint) { setStatus("error"); setMessage("Waitlist is not configured yet. Please add NEXT_PUBLIC_FORMSPREE_ENDPOINT."); return; }
    setStatus("loading"); setMessage("");
    try {
      const response = await fetch(endpoint, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify({ email: normalizedEmail }) });
      if (!response.ok) throw new Error("Waitlist submission failed");
      setStatus("success"); setMessage("You’re on the list. We’ll be in touch soon."); setEmail("");
    } catch { setStatus("error"); setMessage("Something went wrong. Please try again."); }
  }

  return <form onSubmit={submit} className="mx-auto mt-8 max-w-lg" noValidate>
    <div className="flex flex-col gap-2 rounded-xl border border-white/10 bg-white/[0.035] p-2 shadow-xl shadow-black/20 sm:flex-row">
      <label className="sr-only" htmlFor="waitlist-email">Work email</label>
      <input id="waitlist-email" name="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" disabled={status === "loading"} className="min-h-11 flex-1 rounded-lg border border-transparent bg-transparent px-3 text-sm text-white outline-none placeholder:text-zinc-600 focus:border-sky-300/60 disabled:opacity-60" />
      <button type="submit" disabled={status === "loading"} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-sky-300 px-4 text-sm font-semibold text-[#07101a] transition hover:bg-sky-200 focus:outline-none focus:ring-2 focus:ring-sky-200 focus:ring-offset-2 focus:ring-offset-black disabled:cursor-not-allowed disabled:opacity-70">
        {status === "loading" ? <LoaderCircle className="size-4 animate-spin" /> : <>Join waitlist <ArrowRight className="size-4" /></>}
      </button>
    </div>
    <p aria-live="polite" className={`mt-3 min-h-5 text-sm ${status === "error" ? "text-rose-300" : status === "success" ? "text-emerald-300" : "text-zinc-500"}`}>{message || "No spam. Just launch notes and early access."}</p>
  </form>;
}

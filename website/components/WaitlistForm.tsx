"use client";

import { motion } from "framer-motion";
import { FormEvent, useState } from "react";
import { joinWaitlist } from "../actions/waitlist";

type Status = "idle" | "loading" | "success" | "error";

export function WaitlistForm() {
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("loading");
    setError("");

    const result = await joinWaitlist(new FormData(event.currentTarget));

    if (result.success) {
      setStatus("success");
      return;
    }

    setStatus("error");
    setError(result.error ?? "We could not save your email. Please try again.");
  }

  if (status === "success") {
    return <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, ease: "easeOut" }} className="mt-8 rounded-xl border border-white/15 bg-black px-5 py-4 text-sm leading-6 text-zinc-200 shadow-[0_18px_60px_rgba(0,0,0,0.35)]" role="status" aria-live="polite">
      <span className="font-medium text-white">Thank you for joining the waitlist!</span> We will notify you when cguard is live.
    </motion.div>;
  }

  return <form onSubmit={submit} className="mt-8 max-w-xl" noValidate>
    <div className="flex flex-col gap-2 rounded-xl border border-white/20 bg-black p-2 shadow-[0_16px_55px_rgba(0,0,0,0.3)] sm:flex-row">
      <label className="sr-only" htmlFor="waitlist-email">Email address</label>
      <input id="waitlist-email" name="email" type="email" autoComplete="email" required placeholder="you@company.com" disabled={status === "loading"} aria-invalid={status === "error"} aria-describedby={status === "error" ? "waitlist-error" : undefined} className="min-h-11 min-w-0 flex-1 rounded-lg border border-white/20 bg-black px-3 text-sm text-white outline-none placeholder:text-zinc-500 transition focus:border-white/50 focus:ring-2 focus:ring-white/20 disabled:cursor-wait disabled:opacity-60" />
      <button type="submit" disabled={status === "loading"} className="inline-flex min-h-11 items-center justify-center rounded-lg bg-white px-5 text-sm font-semibold text-black transition hover:bg-zinc-200 focus:outline-none focus:ring-2 focus:ring-white/70 focus:ring-offset-2 focus:ring-offset-black disabled:cursor-wait disabled:opacity-70">
        {status === "loading" ? "Joining..." : "Join waitlist"}
      </button>
    </div>
    {status === "error" && <p id="waitlist-error" className="mt-3 text-sm text-red-400" role="alert">{error}</p>}
  </form>;
}

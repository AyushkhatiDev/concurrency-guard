"use client";

import { motion } from "framer-motion";
import { FormEvent, useState } from "react";
import { joinWaitlist } from "../actions/waitlist";

type Status = "idle" | "loading" | "success" | "error";

function nameFromEmail(email: string) {
  const localPart = email.split("@", 1)[0] ?? "there";
  const name = localPart.replace(/[._-]+/g, " ").trim().slice(0, 36);

  return name ? name.replace(/\b\w/g, (character) => character.toUpperCase()) : "there";
}

export function WaitlistForm() {
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState("");
  const [name, setName] = useState("there");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("loading");
    setError("");

    const formData = new FormData(event.currentTarget);
    const email = formData.get("email");
    const result = await joinWaitlist(formData);

    if (result.success) {
      if (typeof email === "string") setName(nameFromEmail(email));
      setStatus("success");
      return;
    }

    setStatus("error");
    setError(result.error ?? "We could not save your email. Please try again.");
  }

  if (status === "success") {
    return <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, ease: "easeOut" }} className="mt-8 rounded-xl border border-white/15 bg-black px-5 py-4 text-sm leading-6 text-zinc-200 shadow-[0_18px_60px_rgba(0,0,0,0.35)]" role="status" aria-live="polite">
      <motion.p initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08, duration: 0.3 }} className="m-0 font-medium text-white">Thank you, {name}.</motion.p>
      <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.18, duration: 0.3 }} className="m-0 text-zinc-400">We will notify you when cguard is live.</motion.p>
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

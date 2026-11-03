"use server";

import { appendFile } from "fs/promises";
import path from "path";

const emailPattern = /^\S+@\S+\.\S+$/;

export async function joinWaitlist(formData: FormData) {
  const email = formData.get("email");

  if (typeof email !== "string" || !emailPattern.test(email.trim())) {
    return { error: "Please enter a valid email address." };
  }

  const timestamp = new Date().toISOString();
  const waitlistPath = path.join(process.cwd(), "waitlist.txt");

  try {
    await appendFile(waitlistPath, `[${timestamp}] ${email.trim()}\n`, "utf8");
    return { success: true };
  } catch {
    return { error: "We could not save your email. Please try again." };
  }
}

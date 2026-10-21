import { type IRouter, type Request } from "express";
import { z } from "zod";
import { usersTable } from "@workspace/db";
import { createSession, SESSION_COOKIE, SESSION_TTL } from "../lib/auth";

/** Pieces shared by the account routes: body schemas, the in-memory attempt limiter and session helpers. */
// Deliberately no composition rules (no "must contain a symbol"). Length is
// what actually resists guessing, and the rest mostly pushes people toward
// Password1! and a sticky note.
export const MIN_PASSWORD_LENGTH = 10;
export const MAX_PASSWORD_LENGTH = 200;

export const RegisterBody = z.object({
  email: z.string().trim().toLowerCase().email("Enter a valid email address"),
  password: z
    .string()
    .min(MIN_PASSWORD_LENGTH, `Use at least ${MIN_PASSWORD_LENGTH} characters`)
    .max(MAX_PASSWORD_LENGTH, "That password is too long"),
});

export const LoginBody = z.object({
  email: z.string().trim().toLowerCase().email("Enter a valid email address"),
  password: z.string().min(1, "Enter your password").max(MAX_PASSWORD_LENGTH, "That password is too long"),
});

/** Any well-formed UUID: for rejecting a malformed id before it reaches a uuid column. */
export const UUID_ANY = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ── Rate limiting ────────────────────────────────────────────────────────────
// Same shape as the limiter already in routes/auth.ts. In-memory, so it resets
// on deploy and is per-instance; adequate against online guessing, and not a
// substitute for the scrypt cost that protects a stolen table.
export const attempts = new Map<string, number[]>();
export const WINDOW_MS = 15 * 60_000;
export const MAX_ATTEMPTS = 10;

const PRUNE_ABOVE = 2_000;

export function isRateLimited(key: string): boolean {
  const now = Date.now();
  // Forged addresses add a key each and nothing else removes them, so sweep stale keys once the map is large.
  if (attempts.size > PRUNE_ABOVE) {
    for (const [k, ts] of attempts) if (!ts.some((t) => now - t < WINDOW_MS)) attempts.delete(k);
  }
  const recent = (attempts.get(key) ?? []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  attempts.set(key, recent);
  return recent.length > MAX_ATTEMPTS;
}

/**
 * Whether this key has already failed MAX_ATTEMPTS times in the window, without counting this
 * look. For per-account login throttling: the IP limit alone lets guesses spread across many
 * addresses all reach one account. Only failures are recorded (recordFailure), so a person who
 * signs in correctly is not counted against.
 */
export function isLockedOut(key: string): boolean {
  const now = Date.now();
  return (attempts.get(key) ?? []).filter((t) => now - t < WINDOW_MS).length >= MAX_ATTEMPTS;
}

export function recordFailure(key: string): void {
  isRateLimited(key);
}

// "al***@example.com" — enough for the user to recognise their own mailbox,
// not enough to hand the address to someone who only guessed the password.
export function maskEmail(address: string): string {
  const at = address.lastIndexOf("@");
  if (at <= 0) return "***";
  const local = address.slice(0, at);
  const domain = address.slice(at);
  const head = local.slice(0, Math.min(2, local.length));
  return `${head}${"*".repeat(Math.max(1, local.length - head.length))}${domain}`;
}

export function publicUser(row: typeof usersTable.$inferSelect) {
  return {
    id: row.id,
    email: row.email,
    firstName: row.firstName,
    lastName: row.lastName,
    profileImageUrl: row.profileImageUrl,
  };
}

export async function startSession(req: Request, res: Parameters<Parameters<IRouter["post"]>[1]>[1], row: typeof usersTable.$inferSelect) {
  const sid = await createSession({
    user: publicUser(row),
    // The OIDC path stores a provider access token here. Password sessions have
    // no upstream token, so this field is unused for them.
    access_token: "",
  });

  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: SESSION_TTL,
    // req.protocol reflects X-Forwarded-Proto only when TRUST_PROXY is set —
    // see the note in app.ts.
    secure: req.protocol === "https",
    path: "/",
  });
}

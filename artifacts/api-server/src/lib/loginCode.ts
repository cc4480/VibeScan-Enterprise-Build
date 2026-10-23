/**
 * Two-factor sign-in codes.
 *
 * A correct password gets you a *challenge*, not a session: a row in
 * pending_logins and a six-digit code emailed to the account's address. The
 * session is issued only when that code comes back. So the two halves are
 * genuinely different factors — a password is something you know, the code
 * proves you can read the mailbox — and neither one alone signs anyone in.
 *
 * WHY THIS IS NOT JUST authTokens WITH A SHORTER VALUE. That module's own
 * header explains that unsalted SHA-256 is the right call for a token because
 * "these tokens are 32 bytes of CSPRNG output, so there is no guessable input
 * to grind against". A six-digit code is a million values. Everything below,
 * and the shape of the pending_logins table, exists to close that gap:
 *
 *  1. A code is matched INSIDE A CHALLENGE, never on its own. The challenge is
 *     32 bytes, and you only get one by passing the password step. A code
 *     lookup by value alone would test each guess against every pending login
 *     in the table at once rather than against one.
 *  2. Five wrong guesses spend the challenge, correct code or not.
 *  3. A new challenge retires the user's earlier ones, so several live codes
 *     never stack up and divide the guessing odds.
 *
 * Remove any of the three and the code stops being a credential.
 */

import { createHash, randomBytes, randomInt, timingSafeEqual } from "node:crypto";

export const LOGIN_CODE_LENGTH = 6;

/** Short, because a live code sits in an inbox. */
export const LOGIN_CODE_TTL_MS = 10 * 60 * 1000;

/** See property 2. Counts wrong guesses against one challenge, not requests. */
export const LOGIN_CODE_MAX_ATTEMPTS = 5;

/**
 * A uniformly random six-digit code, leading zeros preserved.
 *
 * randomInt, not `randomBytes % 1000000`: the modulo of a byte-derived integer
 * is biased toward the low end, shrinking a keyspace that has none to spare.
 */
export function generateLoginCode(): string {
  return String(randomInt(0, 10 ** LOGIN_CODE_LENGTH)).padStart(LOGIN_CODE_LENGTH, "0");
}

/** The opaque handle to a pending login. 32 bytes — a real secret, unlike the code. */
export function generateChallenge(): string {
  return randomBytes(32).toString("base64url");
}

export function hashValue(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

/**
 * Canonicalise what the user typed, or null if it cannot be a code.
 *
 * People paste "123 456" because that is how the email formats it, and phone
 * keyboards add trailing spaces. Accepting the punctuation is not leniency
 * about the secret — the digits must still be exactly right — it stops a
 * correct code burning one of five attempts on its formatting.
 */
export function normalizeLoginCode(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const digits = raw.replace(/[\s-]/g, "");
  return new RegExp(`^\\d{${LOGIN_CODE_LENGTH}}$`).test(digits) ? digits : null;
}

/**
 * Constant-time comparison of two hex digests. timingSafeEqual throws on a
 * length mismatch, which would turn a malformed stored value into a 500 rather
 * than a refused sign-in, hence the guard.
 */
export function hashesEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Why a challenge failed.
 *
 * Callers must collapse these into one response. Separating "wrong code" from
 * "no such challenge" tells an attacker whether a guess was ever live, and
 * separating "expired" from "wrong" tells them their timing was the problem
 * rather than their guess. They exist for logs and for deciding whether to
 * offer a retry.
 */
export type LoginCodeFailure = "invalid" | "expired" | "too_many_attempts";

export type LoginCodeResult =
  | { ok: true; userId: string }
  | { ok: false; reason: LoginCodeFailure };

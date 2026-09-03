/**
 * Single-use tokens for email verification and password reset.
 *
 * Only the SHA-256 of a token is stored. The raw value exists in the email and
 * in the user's URL bar, never in the database — so a dumped table cannot be
 * used to verify an address or seize an account. Lookup is by hash, which works
 * precisely because the hash is deterministic.
 *
 * SHA-256 without a salt or a work factor is the right call here, unlike for
 * passwords: these tokens are 32 bytes of CSPRNG output, so there is no
 * guessable input to grind against. The expiry does the rest.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { db, authTokensTable } from "@workspace/db";
import { and, eq, isNull, lt, or } from "drizzle-orm";

export type TokenPurpose = "email_verify" | "password_reset";

// A reset link is a live credential, so it expires fast. Verification is not,
// so it can last long enough to survive a spam folder and a night's sleep.
const TTL_MS: Record<TokenPurpose, number> = {
  password_reset: 60 * 60 * 1000,
  email_verify: 24 * 60 * 60 * 1000,
};

function hashToken(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

/**
 * Mint a token and return the raw value — the only time it is ever available.
 *
 * Any earlier unused token for the same user and purpose is consumed first, so
 * requesting a new reset link immediately retires the previous one rather than
 * leaving several valid at once.
 */
export async function issueToken(userId: string, purpose: TokenPurpose): Promise<string> {
  await db
    .update(authTokensTable)
    .set({ usedAt: new Date() })
    .where(
      and(
        eq(authTokensTable.userId, userId),
        eq(authTokensTable.purpose, purpose),
        isNull(authTokensTable.usedAt),
      ),
    );

  const raw = randomBytes(32).toString("base64url");

  await db.insert(authTokensTable).values({
    userId,
    tokenHash: hashToken(raw),
    purpose,
    expiresAt: new Date(Date.now() + TTL_MS[purpose]),
  });

  return raw;
}

export interface RedeemResult {
  ok: boolean;
  userId?: string;
  /** Why it failed, for logging — never surfaced verbatim to the caller. */
  reason?: "not_found" | "expired" | "already_used";
}

/**
 * Redeem a token, marking it used in the same step.
 *
 * Returns the owning user id on success. Callers must treat every failure the
 * same way in their response: distinguishing "expired" from "never existed"
 * tells an attacker whether a guessed token was ever real.
 */
export async function redeemToken(raw: string, purpose: TokenPurpose): Promise<RedeemResult> {
  if (!raw) return { ok: false, reason: "not_found" };

  const [row] = await db
    .select()
    .from(authTokensTable)
    .where(and(eq(authTokensTable.tokenHash, hashToken(raw)), eq(authTokensTable.purpose, purpose)));

  if (!row) return { ok: false, reason: "not_found" };
  if (row.usedAt) return { ok: false, reason: "already_used" };
  if (row.expiresAt.getTime() < Date.now()) return { ok: false, reason: "expired" };

  // Conditional update: if two requests race the same link, only the one that
  // still sees usedAt as null wins, so a token cannot be spent twice.
  const claimed = await db
    .update(authTokensTable)
    .set({ usedAt: new Date() })
    .where(and(eq(authTokensTable.id, row.id), isNull(authTokensTable.usedAt)))
    .returning();

  if (claimed.length === 0) return { ok: false, reason: "already_used" };

  return { ok: true, userId: row.userId };
}

/** Housekeeping: drop tokens that are spent or long past their expiry. */
export async function purgeStaleTokens(): Promise<void> {
  const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  await db
    .delete(authTokensTable)
    .where(or(lt(authTokensTable.expiresAt, cutoff), lt(authTokensTable.usedAt, cutoff)));
}

/**
 * Constant-time compare for any place a token is checked outside the database
 * path. Exported mainly so callers are not tempted to use `===`.
 */
export function tokensEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

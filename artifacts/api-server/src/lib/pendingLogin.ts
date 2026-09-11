/**
 * Issuing and redeeming the second factor of a password sign-in.
 *
 * See lib/loginCode.ts for why a six-digit secret needs this shape, and
 * schema/auth.ts for the table. In short: the code is matched inside a
 * challenge that only a correct password produces, five wrong guesses spend it,
 * and a new challenge retires the user's earlier ones.
 */

import { db, pendingLoginsTable } from "@workspace/db";
import { and, eq, isNull } from "drizzle-orm";
import {
  LOGIN_CODE_MAX_ATTEMPTS,
  LOGIN_CODE_TTL_MS,
  type LoginCodeResult,
  generateChallenge,
  generateLoginCode,
  hashValue,
  hashesEqual,
} from "./loginCode";

export interface IssuedChallenge {
  /** Opaque handle for the client to send back with the code. Never stored raw. */
  challenge: string;
  /** The six digits to email. Never stored raw, never logged, never returned to the client. */
  code: string;
}

/**
 * Start a pending login for a user whose password has already been verified.
 *
 * Retiring the user's earlier unused challenges is part of the security model,
 * not housekeeping: several live codes for one account would divide the odds of
 * a blind guess by the number outstanding. It also means the code in the newest
 * email is the one that works, which is what someone who hit "resend" expects.
 */
export async function issueLoginChallenge(userId: string): Promise<IssuedChallenge> {
  await db
    .update(pendingLoginsTable)
    .set({ usedAt: new Date() })
    .where(and(eq(pendingLoginsTable.userId, userId), isNull(pendingLoginsTable.usedAt)));

  const challenge = generateChallenge();
  const code = generateLoginCode();

  await db.insert(pendingLoginsTable).values({
    userId,
    challengeHash: hashValue(challenge),
    codeHash: hashValue(code),
    expiresAt: new Date(Date.now() + LOGIN_CODE_TTL_MS),
  });

  return { challenge, code };
}

/**
 * Redeem a challenge with the code that was emailed for it.
 *
 * Returns the user id on success, having spent the challenge in the same step.
 * A wrong guess costs one of five attempts; the fifth kills the challenge, so a
 * subsequent CORRECT code is refused too — that is the point, not a bug.
 *
 * The attempt is charged before the caller sees a result, so a client that
 * disconnects mid-request cannot test codes for free.
 */
export async function redeemLoginChallenge(challenge: string, code: string): Promise<LoginCodeResult> {
  if (!challenge || !code) return { ok: false, reason: "invalid" };

  const [row] = await db
    .select()
    .from(pendingLoginsTable)
    .where(eq(pendingLoginsTable.challengeHash, hashValue(challenge)));

  if (!row) return { ok: false, reason: "invalid" };
  if (row.usedAt) return { ok: false, reason: "invalid" };
  if (row.expiresAt.getTime() < Date.now()) return { ok: false, reason: "expired" };
  if (row.attempts >= LOGIN_CODE_MAX_ATTEMPTS) return { ok: false, reason: "too_many_attempts" };

  if (!hashesEqual(hashValue(code), row.codeHash)) {
    await db
      .update(pendingLoginsTable)
      .set({ attempts: row.attempts + 1 })
      .where(eq(pendingLoginsTable.id, row.id));
    return { ok: false, reason: "invalid" };
  }

  // Conditional on still being unused, so two requests racing the same code
  // cannot both be told they succeeded. Mirrors authTokens.redeemToken.
  const claimed = await db
    .update(pendingLoginsTable)
    .set({ usedAt: new Date() })
    .where(and(eq(pendingLoginsTable.id, row.id), isNull(pendingLoginsTable.usedAt)))
    .returning();

  if (claimed.length === 0) return { ok: false, reason: "invalid" };
  return { ok: true, userId: row.userId };
}

/**
 * Abandon a user's pending logins — used when they sign in another way, or
 * change their password, so a code mailed a moment ago cannot still be spent.
 */
export async function abandonLoginChallenges(userId: string): Promise<void> {
  await db
    .update(pendingLoginsTable)
    .set({ usedAt: new Date() })
    .where(and(eq(pendingLoginsTable.userId, userId), isNull(pendingLoginsTable.usedAt)));
}

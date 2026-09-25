/**
 * The emailed code that turns a sign-up into an account.
 *
 * Same rules as lib/pendingLogin.ts, for the same reasons: the code only counts
 * inside the challenge step one returned, five wrong guesses spend it, and a new
 * sign-up for the same address retires the earlier one so the newest email's
 * code is the one that works.
 */
import { db, pendingRegistrationsTable, type PendingRegistration } from "@workspace/db";
import { and, eq, isNull } from "drizzle-orm";
import {
  LOGIN_CODE_MAX_ATTEMPTS,
  LOGIN_CODE_TTL_MS,
  generateChallenge,
  generateLoginCode,
  hashValue,
  hashesEqual,
} from "./loginCode";

export interface IssuedRegistration {
  challenge: string;
  code: string;
}

export async function issueRegistrationChallenge(input: {
  email: string;
  passwordHash: string;
  signupNetwork: string | null;
  anonUserId: string | null;
}): Promise<IssuedRegistration> {
  await db
    .update(pendingRegistrationsTable)
    .set({ usedAt: new Date() })
    .where(and(eq(pendingRegistrationsTable.email, input.email), isNull(pendingRegistrationsTable.usedAt)));

  const challenge = generateChallenge();
  const code = generateLoginCode();

  await db.insert(pendingRegistrationsTable).values({
    email: input.email,
    passwordHash: input.passwordHash,
    signupNetwork: input.signupNetwork,
    anonUserId: input.anonUserId,
    challengeHash: hashValue(challenge),
    codeHash: hashValue(code),
    expiresAt: new Date(Date.now() + LOGIN_CODE_TTL_MS),
  });

  return { challenge, code };
}

export type RegistrationResult =
  | { ok: true; pending: PendingRegistration }
  | { ok: false; reason: "invalid" | "expired" | "too_many_attempts" };

/** Redeem a sign-up challenge; spends it on success. The attempt is charged before the result. */
export async function redeemRegistrationChallenge(challenge: string, code: string): Promise<RegistrationResult> {
  if (!challenge || !code) return { ok: false, reason: "invalid" };

  const [row] = await db
    .select()
    .from(pendingRegistrationsTable)
    .where(eq(pendingRegistrationsTable.challengeHash, hashValue(challenge)));

  if (!row || row.usedAt) return { ok: false, reason: "invalid" };
  if (row.expiresAt.getTime() < Date.now()) return { ok: false, reason: "expired" };
  if (row.attempts >= LOGIN_CODE_MAX_ATTEMPTS) return { ok: false, reason: "too_many_attempts" };

  if (!hashesEqual(hashValue(code), row.codeHash)) {
    await db
      .update(pendingRegistrationsTable)
      .set({ attempts: row.attempts + 1 })
      .where(eq(pendingRegistrationsTable.id, row.id));
    return { ok: false, reason: "invalid" };
  }

  const claimed = await db
    .update(pendingRegistrationsTable)
    .set({ usedAt: new Date() })
    .where(and(eq(pendingRegistrationsTable.id, row.id), isNull(pendingRegistrationsTable.usedAt)))
    .returning();

  if (claimed.length === 0) return { ok: false, reason: "invalid" };
  return { ok: true, pending: row };
}

/** Spend a sign-up whose code could not be sent. */
export async function abandonRegistration(email: string): Promise<void> {
  await db
    .update(pendingRegistrationsTable)
    .set({ usedAt: new Date() })
    .where(and(eq(pendingRegistrationsTable.email, email), isNull(pendingRegistrationsTable.usedAt)));
}

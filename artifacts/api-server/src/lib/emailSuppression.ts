/**
 * The list of addresses we must stop mailing.
 *
 * Nothing recorded bounces or complaints before this: every send to a dead
 * address was repeated forever, and every "mark as spam" was invisible. Both
 * erode sender reputation, and reputation is what decides whether the mail
 * people DO want reaches the inbox — including the sign-in codes the apps now
 * depend on.
 *
 * See emailSuppressionsTable for why a complaint suppresses only bulk mail
 * while a hard bounce suppresses everything.
 */

import { db, emailSuppressionsTable } from "@workspace/db";
import { eq } from "drizzle-orm";

/**
 * What a message is FOR, which decides whether a complaint stops it.
 *
 * "account" is mail the recipient's own action asked for right now — a sign-in
 * code, a password reset, a receipt. "bulk" is everything else: monitor alerts,
 * product updates, the welcome email.
 */
export type MailKind = "account" | "bulk";

export type SuppressionScope = "all" | "bulk";
export type SuppressionReason = "hard_bounce" | "complaint" | "manual";

function normalize(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Record an address as undeliverable or unwilling.
 *
 * Upserts on the address: a repeat webhook for the same person updates the row
 * rather than failing on the primary key or piling up duplicates.
 *
 * A later "all" never gets downgraded to "bulk". Someone who complained and
 * whose mailbox was then deleted is both, and the stricter rule is the true
 * one — quietly widening back to bulk-only would resume mailing an address
 * that does not exist.
 */
export async function suppressEmail(
  email: string,
  scope: SuppressionScope,
  reason: SuppressionReason,
  detail?: string,
): Promise<void> {
  const address = normalize(email);
  if (!address) return;

  const existing = await getSuppression(address);
  const effective: SuppressionScope = existing?.scope === "all" ? "all" : scope;

  await db
    .insert(emailSuppressionsTable)
    .values({ email: address, scope: effective, reason, detail: detail ?? null })
    .onConflictDoUpdate({
      target: emailSuppressionsTable.email,
      set: { scope: effective, reason, detail: detail ?? null, updatedAt: new Date() },
    });
}

export async function getSuppression(email: string) {
  const [row] = await db
    .select()
    .from(emailSuppressionsTable)
    .where(eq(emailSuppressionsTable.email, normalize(email)));
  return row;
}

/**
 * Whether sending this kind of mail to this address should be skipped.
 *
 * Deliberately fails OPEN. If the lookup throws — the database is briefly
 * unreachable, the table is missing on a half-migrated deploy — we send. The
 * alternative is that a database hiccup silently stops every sign-in code in
 * the system, which is a far worse failure than one extra message to an address
 * that bounced.
 */
export async function isSuppressed(email: string, kind: MailKind): Promise<boolean> {
  try {
    const row = await getSuppression(email);
    if (!row) return false;
    if (row.scope === "all") return true;
    // scope "bulk": a complaint. Account mail still goes — see MailKind.
    return kind === "bulk";
  } catch {
    return false;
  }
}

/** Lift a suppression, e.g. after a user fixes their address. */
export async function unsuppressEmail(email: string): Promise<void> {
  await db.delete(emailSuppressionsTable).where(eq(emailSuppressionsTable.email, normalize(email)));
}

/**
 * Map a Resend webhook event to a suppression, or null if it warrants none.
 *
 * Kept as a pure function so the decision table is testable without a database
 * or an HTTP request — it is the part most likely to be wrong, and the part
 * whose mistakes are silent.
 */
export function suppressionForEvent(
  type: string,
  data: Record<string, unknown>,
): { email: string; scope: SuppressionScope; reason: SuppressionReason; detail?: string } | null {
  const to = data["to"];
  const email =
    typeof to === "string" ? to : Array.isArray(to) && typeof to[0] === "string" ? (to[0] as string) : "";
  if (!email) return null;

  if (type === "email.complained") {
    return { email, scope: "bulk", reason: "complaint", detail: "marked as spam" };
  }

  if (type === "email.bounced") {
    const bounce = (data["bounce"] ?? {}) as Record<string, unknown>;
    const bounceType = String(bounce["type"] ?? "").toLowerCase();
    const subType = String(bounce["subType"] ?? bounce["sub_type"] ?? "").toLowerCase();
    const message = typeof bounce["message"] === "string" ? (bounce["message"] as string) : undefined;

    // ONLY permanent failures. A soft bounce is a full mailbox or a temporary
    // server problem; it resolves by itself, and suppressing on one would cut
    // off a real user whose inbox was briefly over quota.
    const permanent = bounceType === "hard" || bounceType === "permanent";
    if (!permanent) return null;

    // Amazon SES (which Resend sits on) reports a suppression-list bounce for
    // an address ITS list already holds, which says nothing about this address
    // being dead for us. Treated as permanent anyway: SES will not deliver to
    // it regardless, so continuing to try only burns reputation.
    return {
      email,
      scope: "all",
      reason: "hard_bounce",
      detail: message ?? (subType ? `${bounceType}/${subType}` : bounceType),
    };
  }

  return null;
}

/**
 * Spending a purchased scan credit.
 *
 * The free-scan cap and the credit balance are two different gates and were
 * never connected: routes/credits.ts could read a balance, the Stripe webhook
 * could add to one, and nothing could ever spend from it. POST /scans checked
 * only the trial cap, so a customer who paid would have been refused at the
 * same wall with their credits sitting unused — the system would have taken
 * money and delivered nothing.
 */
import { db, creditsTable } from "@workspace/db";
import { eq, and, gt, sql } from "drizzle-orm";

/**
 * Take exactly one credit from a user, if they have one.
 *
 * The decrement and the check are a single statement on purpose. Reading the
 * balance and then writing it back is a lost-update race: two scans submitted
 * together both read 1, both write 0, and both run — one of them free. The
 * `balance > 0` predicate lives in the WHERE clause so Postgres resolves it
 * under the row lock, and the returned rows say whether this caller was the one
 * that got it.
 *
 * Returns the balance remaining after the spend, or null when there was
 * nothing to take.
 */
export async function spendOneCredit(userId: string): Promise<number | null> {
  const rows = await db
    .update(creditsTable)
    .set({ balance: sql`${creditsTable.balance} - 1`, updatedAt: new Date() })
    .where(and(eq(creditsTable.userId, userId), gt(creditsTable.balance, 0)))
    .returning({ balance: creditsTable.balance });

  return rows[0]?.balance ?? null;
}

/**
 * Put a credit back.
 *
 * A credit is taken before the target is validated, because the alternative —
 * validate, create, then charge — leaves a window where a scan exists that
 * nobody paid for. Taking it first means the rejection paths have to give it
 * back, and this is that. Only ever called for a request that actually spent
 * one, so it does not need a balance predicate.
 */
export async function refundOneCredit(userId: string): Promise<void> {
  await db
    .update(creditsTable)
    .set({ balance: sql`${creditsTable.balance} + 1`, updatedAt: new Date() })
    .where(eq(creditsTable.userId, userId));
}

/** Current balance, 0 when the user has never bought anything. */
export async function creditBalance(userId: string): Promise<number> {
  const [row] = await db
    .select({ balance: creditsTable.balance })
    .from(creditsTable)
    .where(eq(creditsTable.userId, userId));

  return row?.balance ?? 0;
}

/**
 * Everything that moves money-backed state: credits, the subscription, and the
 * per-scan record of what paid for it.
 *
 * Collected here, out of the webhook route, because the rules are the product
 * and they need tests that do not stand up a Stripe webhook to run. The route
 * decides WHICH of these to apply for an event; this module decides HOW.
 *
 * Every write is a single statement that decides and changes in one step.
 * Money state written as read-then-write loses updates under concurrency — a
 * purchase landing while a scan spends a credit, two purchases at once — and
 * each of those loses a customer's money or gives away a scan.
 */
import {
  db,
  creditsTable,
  billingSubscriptionsTable,
  scansTable,
  stripeEventsTable,
} from "@workspace/db";
import { and, eq, gt, inArray, lt, sql } from "drizzle-orm";
import { includedScansForPlan, isUnlimitedPlan } from "./plans";

/** A transaction handle, or the pool itself — every helper accepts either. */
export type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];
export type Executor = typeof db | Tx;

// ── Idempotency ─────────────────────────────────────────────────────────────

/**
 * Record a Stripe event as applied. Returns false when it already was.
 *
 * Must run inside the SAME transaction as the event's effect. Then a duplicate
 * delivery hits the primary key and applies nothing, and a failure part-way
 * rolls the ledger row back with the effect, so Stripe's retry applies it once.
 * Recording it in a separate step would reopen exactly the window this closes.
 */
export async function claimStripeEvent(tx: Executor, event: { id: string; type: string }): Promise<boolean> {
  const rows = await tx
    .insert(stripeEventsTable)
    .values({ id: event.id, type: event.type })
    .onConflictDoNothing()
    .returning({ id: stripeEventsTable.id });
  return rows.length > 0;
}

// ── Credits ─────────────────────────────────────────────────────────────────

/**
 * Add purchased credits. One upsert: the row is created or incremented in a
 * single statement, so a purchase can never overwrite a concurrent spend or a
 * concurrent purchase. The webhook previously read the balance and wrote
 * `existing + n` back — the lost-update race credits.ts warns about for spends.
 */
export async function addCredits(tx: Executor, userId: string, amount: number): Promise<void> {
  if (!Number.isInteger(amount) || amount <= 0) return;
  await tx
    .insert(creditsTable)
    .values({ userId, balance: amount })
    .onConflictDoUpdate({
      target: creditsTable.userId,
      set: { balance: sql`${creditsTable.balance} + ${amount}`, updatedAt: new Date() },
    });
}

// ── Subscription ────────────────────────────────────────────────────────────
// Lives in subscriptions.ts; re-exported so callers keep importing from here.
export {
  mapSubscriptionStatus,
  hasOtherLiveSubscription,
  activateSubscription,
  applyPaidInvoice,
  syncSubscription,
} from "./subscriptions";

// ── Spending a scan ─────────────────────────────────────────────────────────

/**
 * Take one of the plan's included scans, if the user has a live plan with any
 * left. Atomic for the same reason as spendOneCredit: the predicate is in the
 * WHERE clause, so two concurrent scans cannot both take the last one.
 * past_due still spends — see mapSubscriptionStatus.
 */
export async function spendIncludedScan(userId: string): Promise<number | null> {
  const rows = await db
    .update(billingSubscriptionsTable)
    .set({
      includedScansRemaining: sql`${billingSubscriptionsTable.includedScansRemaining} - 1`,
      updatedAt: new Date(),
    })
    .where(
      and(
        eq(billingSubscriptionsTable.userId, userId),
        gt(billingSubscriptionsTable.includedScansRemaining, 0),
        inArray(billingSubscriptionsTable.status, ["active", "past_due"]),
      ),
    )
    .returning({ remaining: billingSubscriptionsTable.includedScansRemaining });
  return rows[0]?.remaining ?? null;
}

/**
 * Give an included scan back (a launch that was rejected, or a scan that failed).
 *
 * Only a live plan can take it back. If the plan has since been cancelled or
 * paused, the scan is returned as a credit instead — otherwise a refund to a
 * cancelled plan would vanish, and someone charged for a scan that failed
 * would get nothing back.
 */
export async function refundIncludedScan(tx: Executor, userId: string): Promise<void> {
  // An unlimited plan keeps no counter, so there is nothing to put back, and a credit would
  // be a scan the person never paid for. Looked up first because a counter row is the
  // only kind this function can restore.
  const [held] = await tx
    .select({ plan: billingSubscriptionsTable.plan })
    .from(billingSubscriptionsTable)
    .where(eq(billingSubscriptionsTable.userId, userId))
    .limit(1);
  if (held && isUnlimitedPlan(held.plan)) return;

  const restored = await tx
    .update(billingSubscriptionsTable)
    .set({
      includedScansRemaining: sql`${billingSubscriptionsTable.includedScansRemaining} + 1`,
      updatedAt: new Date(),
    })
    .where(and(eq(billingSubscriptionsTable.userId, userId), inArray(billingSubscriptionsTable.status, ["active", "past_due"])))
    .returning({ id: billingSubscriptionsTable.id });
  if (restored.length === 0) await addCredits(tx, userId, 1);
}

/**
 * A scan failed after it was paid for: give the payment back, exactly once.
 *
 * The scan row is read under a row lock and its `paid_with` cleared in the
 * same transaction, so however many times the failure path runs — a job
 * retried, two workers racing a timeout — only the first call sees a payment
 * to return. Free trial
 * scans are left alone: returning one would need un-counting a scan that did
 * happen, and the trial is not money.
 */
export async function refundFailedScan(scanId: string): Promise<"credit" | "included" | null> {
  return db.transaction(async (tx) => {
    // RETURNING reports the row AFTER the update, where paid_with is already
    // NULL — useless for knowing what to refund. So the old value is read
    // under a row lock (FOR UPDATE) in the same transaction, then cleared.
    // A second caller blocks on the lock and then sees NULL: nothing to give.
    const [row] = await tx
      .select({ userId: scansTable.userId, paidWith: scansTable.paidWith })
      .from(scansTable)
      .where(eq(scansTable.id, scanId))
      .for("update");

    if (!row || (row.paidWith !== "credit" && row.paidWith !== "included")) return null;

    await tx.update(scansTable).set({ paidWith: null }).where(eq(scansTable.id, scanId));

    if (row.paidWith === "credit") {
      await addCredits(tx, row.userId, 1);
    } else {
      await refundIncludedScan(tx, row.userId);
    }
    return row.paidWith;
  });
}

/**
 * Fail and refund scans that will never finish.
 *
 * A scan whose job dies outright — the worker OOM-killed mid-scan, every
 * retry exhausted — never reaches the worker's own failure path, so nothing
 * marked it failed and nothing refunded it: it sat "scanning" forever, and a
 * paid scan kept the customer's money. A scan job gets at most 3 attempts of
 * up to 2 hours each (queue.ts), so anything unfinished after
 * STUCK_SCAN_AFTER_MS is dead, not slow.
 *
 * The status update is guarded on the status still being unfinished, so a
 * scan that completes at the same moment is left alone; the worker, for its
 * part, refuses to start a scan already marked failed (worker.ts).
 */
export const STUCK_SCAN_AFTER_MS = 8 * 60 * 60 * 1000;

export async function reapStuckScans(now = new Date()): Promise<{ failed: number; refunded: number }> {
  const cutoff = new Date(now.getTime() - STUCK_SCAN_AFTER_MS);
  const stuck = await db
    .update(scansTable)
    .set({
      status: "failed",
      error: "The scan did not finish. Anything it cost has been returned.",
      completedAt: now,
      // The promise is that stored logins are discarded when a scan ends, and a dead scan has ended.
      credentialsEncrypted: null,
      secondaryCredentialsEncrypted: null,
    })
    .where(
      and(
        inArray(scansTable.status, ["paid", "queued", "scanning", "analyzing"]),
        lt(scansTable.createdAt, cutoff),
      ),
    )
    .returning({ id: scansTable.id });

  let refunded = 0;
  for (const { id } of stuck) {
    if (await refundFailedScan(id)) refunded++;
  }
  return { failed: stuck.length, refunded };
}

/**
 * Does this account have a plan that is currently paying for monitoring?
 *
 * Read from the billing row directly, NOT through monitorEntitlement: that
 * short-circuits to "no plan" while MONITORING_REQUIRES_PLAN is off, which
 * would treat a paying Pro subscriber exactly like a free user. active and
 * past_due count (a card being retried keeps its service); paused and
 * cancelled do not. A grandfathered row counts unless cancelled.
 */
export async function hasLivePlan(userId: string): Promise<boolean> {
  const [row] = await db
    .select({ status: billingSubscriptionsTable.status, grandfathered: billingSubscriptionsTable.grandfathered })
    .from(billingSubscriptionsTable)
    .where(eq(billingSubscriptionsTable.userId, userId))
    .limit(1);
  if (!row || row.status === "cancelled") return false;
  return row.grandfathered || row.status === "active" || row.status === "past_due";
}

/**
 * Does this account hold a live unlimited plan? active and past_due count, the same as
 * for a counted plan (a card being retried keeps its service); paused and cancelled do not.
 */
export async function hasUnlimitedPlan(userId: string): Promise<boolean> {
  const [row] = await db
    .select({ plan: billingSubscriptionsTable.plan, status: billingSubscriptionsTable.status })
    .from(billingSubscriptionsTable)
    .where(eq(billingSubscriptionsTable.userId, userId))
    .limit(1);
  return !!row && isUnlimitedPlan(row.plan) && (row.status === "active" || row.status === "past_due");
}

export type PaidWith = "free" | "included" | "credit";

/**
 * Pay for one scan, in the product's one spend order: an unlimited plan first, then the
 * free trial, then a counted plan's included scans (they expire), then credits (they
 * never do; none are sold any more, but a balance still spends). Returns
 * what paid, or null when nothing is left.
 *
 * The ONE place this order lives — the scan form, the MCP endpoint and the
 * Monitor page all charge through it, so a way in cannot price differently.
 * A "free" charge takes nothing now: the scan row, marked paid_with 'free',
 * is itself what counts against the trial (see freeTrial.ts).
 */
export async function chargeScan(userId: string): Promise<PaidWith | null> {
  // An unlimited plan pays for every scan, and is checked first so a subscriber never
  // spends the month's free scans (which exist for people who have not subscribed).
  if (await hasUnlimitedPlan(userId)) return "included";
  const { trialScansExhausted } = await import("./freeTrial");
  if (!(await trialScansExhausted(userId))) return "free";
  if ((await spendIncludedScan(userId)) !== null) return "included";
  const { spendOneCredit } = await import("./credits");
  if ((await spendOneCredit(userId)) !== null) return "credit";
  return null;
}

/** Give back a charge whose scan was never created. */
export async function refundCharge(userId: string, paidWith: PaidWith | null): Promise<void> {
  if (paidWith === "credit") await addCredits(db, userId, 1);
  else if (paidWith === "included") await refundIncludedScan(db, userId);
  // "free" and null took nothing, so there is nothing to return.
}

export { includedScansForPlan };

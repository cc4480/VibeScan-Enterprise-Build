/**
 * The subscription rows: starting a plan, granting a period's scans, mirroring
 * Stripe's status. Split out of billing.ts, which re-exports all of it, so the
 * file that holds one-plan-per-user rules stays small enough to read.
 *
 * One plan per user (billing_subscriptions.user_id is unique). That row can only
 * describe ONE Stripe subscription, so a second live one must never be written
 * over the first: Stripe would go on billing a subscription the database no
 * longer knows about. See hasOtherLiveSubscription.
 */
import { billingSubscriptionsTable } from "@workspace/db";
import { and, eq, ne, sql } from "drizzle-orm";
import { DEFAULT_PLAN, MONITOR_PLANS, type MonitorPlan } from "./plans";
import type { Executor } from "./billing";

/** Stripe's subscription status mapped onto ours. See entitlements.ts. */
export function mapSubscriptionStatus(
  stripeStatus: string,
): "active" | "past_due" | "paused" | "cancelled" {
  switch (stripeStatus) {
    case "active":
    case "trialing":
      return "active";
    // Stripe is still retrying the card. Access continues — cutting off a
    // paying customer over a card that is about to succeed is the worse error.
    case "past_due":
      return "past_due";
    // Retries exhausted, or the subscription was paused: stop scanning, keep
    // history readable.
    case "unpaid":
    case "paused":
    case "incomplete":
      return "paused";
    // canceled, incomplete_expired
    default:
      return "cancelled";
  }
}

/**
 * True when this user already has a live plan that belongs to a DIFFERENT Stripe
 * subscription. Checkout sessions are created one at a time but can be paid in
 * parallel (two tabs, a double click, a retried link), and the "already
 * subscribed" check at session creation cannot see a payment that has not
 * happened yet. A cancelled row, or a grandfathered one with no Stripe
 * subscription, is not live and may be replaced.
 */
export async function hasOtherLiveSubscription(
  tx: Executor,
  userId: string,
  stripeSubscriptionId: string,
): Promise<boolean> {
  const [row] = await tx
    .select({ sub: billingSubscriptionsTable.stripeSubscriptionId, status: billingSubscriptionsTable.status })
    .from(billingSubscriptionsTable)
    .where(eq(billingSubscriptionsTable.userId, userId));
  return !!row && !!row.sub && row.sub !== stripeSubscriptionId && row.status !== "cancelled";
}

/**
 * Create or refresh the user's plan row when a subscription starts.
 *
 * Does NOT grant the included scans: the paid invoice does that. Checkout
 * completing and the first invoice being paid are separate events that Stripe
 * may deliver in either order, and allowance must follow money actually taken,
 * not the checkout page closing.
 */
export async function activateSubscription(
  tx: Executor,
  opts: {
    userId: string;
    stripeCustomerId: string | null;
    stripeSubscriptionId: string;
    currentPeriodEnd: Date | null;
    /** The plan bought, from the session or subscription metadata. */
    plan?: MonitorPlan;
  },
): Promise<"activated" | "duplicate"> {
  if (await hasOtherLiveSubscription(tx, opts.userId, opts.stripeSubscriptionId)) return "duplicate";
  const plan = opts.plan ?? DEFAULT_PLAN;
  await tx
    .insert(billingSubscriptionsTable)
    .values({
      userId: opts.userId,
      plan: plan.key,
      status: "active",
      urlLimit: plan.urlLimit,
      currentPeriodEnd: opts.currentPeriodEnd,
      stripeCustomerId: opts.stripeCustomerId,
      stripeSubscriptionId: opts.stripeSubscriptionId,
      grandfathered: false,
    })
    .onConflictDoUpdate({
      target: billingSubscriptionsTable.userId,
      set: {
        plan: plan.key,
        status: "active",
        urlLimit: plan.urlLimit,
        currentPeriodEnd: opts.currentPeriodEnd,
        stripeCustomerId: opts.stripeCustomerId,
        stripeSubscriptionId: opts.stripeSubscriptionId,
        updatedAt: new Date(),
      },
    });
  return "activated";
}

/**
 * A subscription invoice was paid: (re)start the period's included scans.
 *
 * SETS the allowance to the plan's amount rather than adding to it. Unused
 * scans therefore do not roll over, and — together with the event ledger — a
 * redelivered invoice.paid cannot stack a second month's scans.
 *
 * If the plan row does not exist yet (invoice.paid can beat
 * checkout.session.completed), it is created from the invoice's own
 * subscription metadata, so the order Stripe happens to use does not matter.
 */
export async function applyPaidInvoice(
  tx: Executor,
  opts: {
    stripeSubscriptionId: string;
    stripeCustomerId: string | null;
    userId: string | null;
    currentPeriodEnd: Date | null;
    /** The plan named in the subscription metadata, for the row-does-not-exist-yet case. */
    plan?: MonitorPlan;
  },
): Promise<"applied" | "unknown_subscription" | "duplicate" | "stale"> {
  // Each plan's allowance, chosen by the plan stored on the row, so a Starter
  // invoice grants Starter's scans. Every known plan is listed, sold or not, so a row on a
  // plan that is no longer sold is still granted its scans; an unlimited plan grants 0
  // because it keeps no counter. A row whose plan is not in the table keeps what it has.
  const allowance = sql.join(
    Object.values(MONITOR_PLANS).map((p) => sql`WHEN ${billingSubscriptionsTable.plan} = ${p.key} THEN ${p.includedScans}`),
    sql` `,
  );
  const updated = await tx
    .update(billingSubscriptionsTable)
    .set({
      status: "active",
      includedScansRemaining: sql`CASE ${allowance} ELSE ${billingSubscriptionsTable.includedScansRemaining} END`,
      currentPeriodEnd: opts.currentPeriodEnd,
      updatedAt: new Date(),
    })
    // A cancelled subscription is final in Stripe, so an invoice.paid for it that arrives now
    // is a late retry delivered out of order, not a renewal. It must not turn the plan back on.
    .where(and(eq(billingSubscriptionsTable.stripeSubscriptionId, opts.stripeSubscriptionId), ne(billingSubscriptionsTable.status, "cancelled")))
    .returning({ id: billingSubscriptionsTable.id });

  if (updated.length > 0) return "applied";
  const cancelled = await tx
    .select({ id: billingSubscriptionsTable.id })
    .from(billingSubscriptionsTable)
    .where(eq(billingSubscriptionsTable.stripeSubscriptionId, opts.stripeSubscriptionId))
    .limit(1);
  if (cancelled.length > 0) return "stale";
  if (!opts.userId) return "unknown_subscription";

  const plan = opts.plan ?? DEFAULT_PLAN;
  const started = await activateSubscription(tx, {
    userId: opts.userId,
    stripeCustomerId: opts.stripeCustomerId,
    stripeSubscriptionId: opts.stripeSubscriptionId,
    currentPeriodEnd: opts.currentPeriodEnd,
    plan,
  });
  if (started === "duplicate") return "duplicate";
  await tx
    .update(billingSubscriptionsTable)
    .set({ includedScansRemaining: plan.includedScans })
    .where(eq(billingSubscriptionsTable.userId, opts.userId));
  return "applied";
}

/**
 * Mirror a subscription's status and period from Stripe onto the plan row.
 *
 * Stripe does not deliver events in order, and "canceled" is terminal, so a cancelled row is
 * left alone: a customer.subscription.updated that lands after .deleted must not revive it.
 */
export async function syncSubscription(
  tx: Executor,
  opts: { stripeSubscriptionId: string; stripeStatus: string; currentPeriodEnd: Date | null },
): Promise<void> {
  const status = mapSubscriptionStatus(opts.stripeStatus);
  await tx
    .update(billingSubscriptionsTable)
    .set({
      status,
      currentPeriodEnd: opts.currentPeriodEnd,
      // A cancelled plan keeps nothing it has not used. Otherwise the scans
      // would outlive the subscription that paid for them.
      ...(status === "cancelled" ? { includedScansRemaining: 0 } : {}),
      updatedAt: new Date(),
    })
    .where(and(eq(billingSubscriptionsTable.stripeSubscriptionId, opts.stripeSubscriptionId), ne(billingSubscriptionsTable.status, "cancelled")));
}

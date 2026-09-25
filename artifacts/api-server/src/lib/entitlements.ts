/**
 * What a user is allowed to monitor.
 *
 * Monitoring is currently free, unlimited, and ungated: the sweep checks only
 * that a subscription row says "active" and has not passed its expiresAt, and
 * expiresAt is set to a year out at creation with no payment involved. The
 * free-scan cap applies when creating a subscription and never again, so the
 * scheduler keeps rescanning after it is spent. That is the hole this closes.
 *
 * IT IS OFF BY DEFAULT. `MONITORING_REQUIRES_PLAN` gates every check here, so
 * deploying this changes nothing until the variable is set — the same shape as
 * the dormant checkout work. Turning it on before subscriptions can be bought
 * would lock every existing user out of a feature they are using today, so the
 * flag flips when Phase 3 ships, not before.
 */
import { db, billingSubscriptionsTable } from "@workspace/db";
import { eq } from "drizzle-orm";

export type EntitlementReason =
  | "unenforced"
  | "grandfathered"
  | "active"
  | "grace_period"
  | "paused"
  | "cancelled"
  | "no_plan";

export interface MonitorEntitlement {
  /** May the scheduler rescan, and may alerts be sent, for this user? */
  monitoringActive: boolean;
  /** How many URLs this user may monitor at once. */
  urlLimit: number;
  plan: string | null;
  /** Machine-readable cause, for logs and for telling the user what to do. */
  reason: EntitlementReason;
}

/** The shape resolveEntitlement needs — a subset of the billing row. */
export interface BillingRow {
  plan: string;
  status: string;
  urlLimit: number;
  grandfathered: boolean;
}

/** Whether plan enforcement is switched on for this deployment. */
export function enforcementEnabled(): boolean {
  return process.env["MONITORING_REQUIRES_PLAN"] === "true";
}

/**
 * Whether a monitor's own expiresAt still ends it.
 *
 * Only while plans are unenforced. expiresAt is a year out from creation and
 * has nothing to do with payment, so under a monthly plan it would stop a
 * paying customer's monitors in month 12 and keep a cancelled one running.
 * Once MONITORING_REQUIRES_PLAN is on, the plan decides: active or past_due
 * keeps monitors running, cancelled or paused stops them (the rows are kept,
 * and they resume if the plan does).
 */
export function monitorExpiryApplies(): boolean {
  return !enforcementEnabled();
}

/**
 * Decide what a user may do, from their billing row alone.
 *
 * Pure on purpose: this is the rule that decides whether a paying customer's
 * site keeps being watched, and it should be testable without a database.
 *
 * `past_due` deliberately stays ACTIVE. Stripe retries a failed card for days,
 * and cutting monitoring off on the first failed charge would stop watching a
 * customer's site over a card that is about to succeed. The paused state is
 * what stops scanning, and only the billing webhook sets it, after the retries
 * are exhausted.
 */
export function resolveEntitlement(
  row: BillingRow | null,
  opts: { enforced: boolean },
): MonitorEntitlement {
  if (!opts.enforced) {
    // Today's behaviour, preserved exactly: everyone may monitor anything.
    return {
      monitoringActive: true,
      urlLimit: Number.POSITIVE_INFINITY,
      plan: row?.plan ?? null,
      reason: "unenforced",
    };
  }

  if (!row) {
    return { monitoringActive: false, urlLimit: 0, plan: null, reason: "no_plan" };
  }

  // Cancelled wins over grandfathered: someone who asked to stop has stopped,
  // however they got their allowance.
  if (row.status === "cancelled") {
    return { monitoringActive: false, urlLimit: row.urlLimit, plan: row.plan, reason: "cancelled" };
  }

  if (row.grandfathered) {
    return { monitoringActive: true, urlLimit: row.urlLimit, plan: row.plan, reason: "grandfathered" };
  }

  if (row.status === "paused") {
    return { monitoringActive: false, urlLimit: row.urlLimit, plan: row.plan, reason: "paused" };
  }

  if (row.status === "past_due") {
    return { monitoringActive: true, urlLimit: row.urlLimit, plan: row.plan, reason: "grace_period" };
  }

  return { monitoringActive: true, urlLimit: row.urlLimit, plan: row.plan, reason: "active" };
}

/**
 * Resolve a user's entitlement, reading their billing row.
 *
 * Fails OPEN on a database error, and the choice is deliberate: the cost of
 * wrongly allowing a scan is one scan, while the cost of wrongly refusing is
 * that a paying customer's site silently stops being watched and nobody finds
 * out until something is exploited. The same reasoning as alertEmailsAllowed
 * in mailer.ts.
 */
export async function monitorEntitlement(userId: string): Promise<MonitorEntitlement> {
  const enforced = enforcementEnabled();
  if (!enforced) return resolveEntitlement(null, { enforced: false });

  try {
    const [row] = await db
      .select({
        plan: billingSubscriptionsTable.plan,
        status: billingSubscriptionsTable.status,
        urlLimit: billingSubscriptionsTable.urlLimit,
        grandfathered: billingSubscriptionsTable.grandfathered,
      })
      .from(billingSubscriptionsTable)
      .where(eq(billingSubscriptionsTable.userId, userId))
      .limit(1);

    return resolveEntitlement(row ?? null, { enforced });
  } catch (err) {
    console.error("[entitlements] Could not read billing row; allowing:", err);
    return {
      monitoringActive: true,
      urlLimit: Number.POSITIVE_INFINITY,
      plan: null,
      reason: "unenforced",
    };
  }
}

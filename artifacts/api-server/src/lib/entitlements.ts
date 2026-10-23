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
 *
 * When it does flip, an account with no plan keeps one free site (freeMonitorSites)
 * instead of losing monitoring outright. Accounts already monitoring more than that
 * are covered by their grandfathered billing rows, not by this rule.
 */
import { db, billingSubscriptionsTable } from "@workspace/db";
import { eq } from "drizzle-orm";

export type EntitlementReason =
  | "unenforced"
  | "free"
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

/**
 * Sites an account with no plan may watch once plans are enforced.
 *
 * One free site gives a person who tried the product a reason to come back: the
 * hourly pulse, the CVE match and the certificate alerts cost almost nothing, and
 * the rescans are held to weekly (see FREE_MONITOR_MIN_DAYS). FREE_MONITOR_SITES=0
 * turns the free site off and restores "monitoring needs a plan". Read on each
 * call so a test, or an operator restart, changes it without a code edit.
 */
export function freeMonitorSites(): number {
  const raw = process.env["FREE_MONITOR_SITES"];
  if (raw === undefined || raw.trim() === "") return 1;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : 1;
}

/**
 * The shortest gap between full rescans of a free account's site. The grade-based
 * cadence runs as often as every 3 days at D or F; a free site is held to weekly so
 * the free tier stays cheap. A paid plan keeps the grade-based cadence.
 */
export const FREE_MONITOR_MIN_DAYS = 7;

/**
 * The rescan floor, in days, for an account's monitored sites. Weekly for an account
 * with no live plan once plans are enforced, none otherwise. Unenforced, nobody is on
 * a "free plan" yet, so today's grade-based cadence is untouched.
 */
export function rescanFloorDays(opts: { enforced: boolean; hasLivePlan: boolean }): number {
  return opts.enforced && !opts.hasLivePlan ? FREE_MONITOR_MIN_DAYS : 0;
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
  /**
   * `freeSites` is how many sites an account with no billing row may watch. It
   * defaults to 0, which keeps this function's old answer ("no plan, no
   * monitoring") for any caller that does not opt in; monitorEntitlement passes
   * the deployment's setting.
   */
  opts: { enforced: boolean; freeSites?: number },
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
    // Never had a plan. Only these accounts get the free site: a cancelled or
    // paused row is a decision someone made, handled below.
    const freeSites = opts.freeSites ?? 0;
    if (freeSites > 0) {
      return { monitoringActive: true, urlLimit: freeSites, plan: null, reason: "free" };
    }
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

    return resolveEntitlement(row ?? null, { enforced, freeSites: freeMonitorSites() });
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

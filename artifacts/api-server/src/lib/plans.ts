/**
 * The monitoring subscription.
 *
 * One plan, by decision (2026-09-22): $50/month buys continuous monitoring for
 * up to 3 sites plus 5 full scans each billing period. It replaced a
 * Solo/Studio/Agency ladder that was designed but never sold — one plan is
 * easier to sell and to explain, and tiers can come back if agencies ask.
 *
 * Kept beside the credit pricing in stripe.ts rather than inside it, because a
 * plan is a different product with a different billing mode: credits are a
 * one-time purchase, a plan is a recurring subscription.
 *
 * `urlLimit` and `includedScans` are the published allowance. `urlLimit` is
 * copied onto the billing_subscriptions row at signup rather than read from
 * here at check time, so that changing the plan later does not silently
 * rewrite what an existing customer was already sold. `includedScans` is
 * applied on each paid invoice.
 */

export interface MonitorPlan {
  /** Stable key stored on the subscription row. */
  key: "pro";
  name: string;
  /** Monthly price in the smallest currency unit, as Stripe wants it. */
  amountCents: number;
  /** Sites that may be monitored at once. */
  urlLimit: number;
  /** Full scans included per billing period. Unused scans do not roll over. */
  includedScans: number;
  description: string;
}

export const MONITOR_PLANS: Record<MonitorPlan["key"], MonitorPlan> = {
  pro: {
    key: "pro",
    name: "SecScan Pro",
    amountCents: 5000,
    urlLimit: 3,
    includedScans: 5,
    description: "Continuous monitoring for up to 3 sites, plus 5 full scans every month",
  },
};

/** The one plan that is sold. */
export const DEFAULT_PLAN: MonitorPlan = MONITOR_PLANS.pro;

/** The allowance for a plan key, or null if the key is not a sellable plan. */
export function urlLimitForPlan(plan: string): number | null {
  const found = MONITOR_PLANS[plan as MonitorPlan["key"]];
  return found ? found.urlLimit : null;
}

/** Scans a plan includes per period, or 0 for anything that is not a sold plan. */
export function includedScansForPlan(plan: string): number {
  return MONITOR_PLANS[plan as MonitorPlan["key"]]?.includedScans ?? 0;
}

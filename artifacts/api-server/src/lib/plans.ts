/**
 * The monitoring subscriptions.
 *
 * Two plans, by decision (2026-09-24), priced against the rivals in the
 * competitive landscape (CheckVibe, Vibe App Scanner: $19–$49 a month for 20–250
 * scans). The single $50 plan it replaced gave 3 sites and 5 scans, several times
 * the market's price per scan.
 *
 *   Starter  $19/month  1 site watched   20 scans a month
 *   Pro      $49/month  5 sites watched  100 scans a month
 *
 * Kept beside the credit pricing in stripe.ts rather than inside it, because a
 * plan is a different product with a different billing mode: credits are a
 * one-time purchase, a plan is a recurring subscription.
 *
 * `urlLimit` and `includedScans` are the published allowance. `urlLimit` is
 * copied onto the billing_subscriptions row at signup rather than read from
 * here at check time, so that changing a plan later does not silently rewrite
 * what an existing customer was already sold. `includedScans` is applied on
 * each paid invoice, from the plan stored on the row.
 */
export type PlanKey = "starter" | "pro";

export interface MonitorPlan {
  /** Stable key stored on the subscription row and in Stripe metadata. */
  key: PlanKey;
  name: string;
  /** Monthly price in the smallest currency unit, as Stripe wants it. */
  amountCents: number;
  /** Sites that may be monitored at once. */
  urlLimit: number;
  /** Full scans included per billing period. Unused scans do not roll over. */
  includedScans: number;
  description: string;
}

export const MONITOR_PLANS: Record<PlanKey, MonitorPlan> = {
  starter: {
    key: "starter",
    name: "SecScan Starter",
    amountCents: 1900,
    urlLimit: 1,
    includedScans: 20,
    description: "1 site watched around the clock, plus 20 full scans every month",
  },
  pro: {
    key: "pro",
    name: "SecScan Pro",
    amountCents: 4900,
    urlLimit: 5,
    includedScans: 100,
    description: "Up to 5 sites watched around the clock, plus 100 full scans every month",
  },
};

/** The plans on sale, cheapest first. */
export const SOLD_PLANS: MonitorPlan[] = [MONITOR_PLANS.starter, MONITOR_PLANS.pro];

/** The plan used when Stripe metadata names none (subscriptions started before plans had keys). */
export const DEFAULT_PLAN: MonitorPlan = MONITOR_PLANS.pro;

/** A sold plan by key, or null for anything that is not one. */
export function planByKey(key: string | null | undefined): MonitorPlan | null {
  // hasOwn, not `in`: `in` also finds prototype names, so "constructor" from
  // Stripe metadata would have resolved to Object itself.
  return key && Object.hasOwn(MONITOR_PLANS, key) ? MONITOR_PLANS[key as PlanKey] : null;
}

/** The allowance for a plan key, or null if the key is not a sellable plan. */
export function urlLimitForPlan(plan: string): number | null {
  return planByKey(plan)?.urlLimit ?? null;
}

/** Scans a plan includes per period, or 0 for anything that is not a sold plan. */
export function includedScansForPlan(plan: string): number {
  return planByKey(plan)?.includedScans ?? 0;
}

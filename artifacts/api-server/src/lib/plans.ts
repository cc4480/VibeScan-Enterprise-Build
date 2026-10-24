/**
 * The monitoring subscription.
 *
 * ONE plan is sold, by decision (2026-10-03): SecScan Unlimited, $19 a month, unlimited
 * scans and 3 sites watched (changed from 5 on 2026-10-24). It replaces the two-plan table of 2026-09-24 (Starter $19 for
 * 20 scans, Pro $49 for 100), priced against rivals that sell unlimited scans for $8 to
 * $24 a month (VibeEval, SafeToShip, ZeriFlow). Counting scans was the confusing part of
 * the old plans, and with unlimited scans the two tiers would have differed by two sites.
 *
 * "Unlimited" is fair use, not an absence of limits: the per-account rate limits in
 * rateLimit.ts and scansCreate.ts (5 an hour, 20 a day) still apply.
 *
 * Starter and Pro stay in the table, NOT sold, so a subscription row that carries one of
 * those keys still resolves to its allowance and keeps being granted its scans on each
 * paid invoice. Nobody holds one (payments were never switched on), and removing the keys
 * would make such a row look like an unknown plan.
 *
 * Kept beside the credit pricing in stripe.ts rather than inside it, because a plan is a
 * different product with a different billing mode: a plan is a recurring subscription.
 *
 * `urlLimit` and `includedScans` are the published allowance. `urlLimit` is copied onto
 * the billing_subscriptions row at signup rather than read from here at check time, so
 * that changing a plan later does not silently rewrite what an existing customer was
 * already sold. `includedScans` is applied on each paid invoice, from the plan stored on
 * the row; it is 0 for an unlimited plan, which keeps no counter (see spendIncludedScan).
 */
export type PlanKey = "starter" | "pro" | "unlimited";

export interface MonitorPlan {
  /** Stable key stored on the subscription row and in Stripe metadata. */
  key: PlanKey;
  name: string;
  /** Monthly price in the smallest currency unit, as Stripe wants it. */
  amountCents: number;
  /** Sites that may be monitored at once. */
  urlLimit: number;
  /** Full scans included per billing period. Unused scans do not roll over. 0 when `unlimitedScans`. */
  includedScans: number;
  /** Scans are not counted, only rate-limited. */
  unlimitedScans: boolean;
  description: string;
}

export const MONITOR_PLANS: Record<PlanKey, MonitorPlan> = {
  starter: {
    key: "starter",
    name: "SecScan Starter",
    amountCents: 1900,
    urlLimit: 3,
    includedScans: 20,
    unlimitedScans: false,
    description: "Up to 3 sites watched around the clock, plus 20 full scans every month",
  },
  pro: {
    key: "pro",
    name: "SecScan Pro",
    amountCents: 4900,
    urlLimit: 5,
    includedScans: 100,
    unlimitedScans: false,
    description: "Up to 5 sites watched around the clock, plus 100 full scans every month",
  },
  unlimited: {
    key: "unlimited",
    name: "SecScan Unlimited",
    amountCents: 1900,
    urlLimit: 3,
    includedScans: 0,
    unlimitedScans: true,
    description: "Unlimited full scans and up to 3 sites watched around the clock",
  },
};

/** The plans on sale, cheapest first. */
export const SOLD_PLANS: MonitorPlan[] = [MONITOR_PLANS.unlimited];

/** The plan used when a request or Stripe metadata names none. It is the one plan on sale. */
export const DEFAULT_PLAN: MonitorPlan = MONITOR_PLANS.unlimited;

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

/** Does this plan key sell unlimited scans? False for anything that is not a known plan. */
export function isUnlimitedPlan(plan: string | null | undefined): boolean {
  return planByKey(plan)?.unlimitedScans === true;
}

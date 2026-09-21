/**
 * Monitoring plans.
 *
 * Kept beside the credit pricing in stripe.ts rather than inside it, because
 * these are a different product with a different billing mode: credits are a
 * one-time purchase, a plan is a recurring subscription. Phase 3 adds the
 * Stripe price ids here; nothing reads them yet.
 *
 * `urlLimit` is the published allowance for the tier. It is copied onto a
 * billing_subscriptions row at signup rather than read from here at check
 * time, so that changing a tier later does not silently rewrite what an
 * existing customer was already sold.
 */

export interface MonitorPlan {
  /** Stable key stored on the subscription row. */
  key: "solo" | "studio" | "agency";
  name: string;
  /** Monthly price in the smallest currency unit, as Stripe wants it. */
  amountCents: number;
  urlLimit: number;
  description: string;
}

export const MONITOR_PLANS: Record<MonitorPlan["key"], MonitorPlan> = {
  solo: {
    key: "solo",
    name: "Solo",
    amountCents: 1900,
    urlLimit: 3,
    description: "Continuous monitoring for up to 3 sites",
  },
  studio: {
    key: "studio",
    name: "Studio",
    amountCents: 4900,
    urlLimit: 10,
    description: "Continuous monitoring for up to 10 sites",
  },
  agency: {
    key: "agency",
    name: "Agency",
    amountCents: 14900,
    urlLimit: 40,
    description: "Continuous monitoring for up to 40 sites — for agencies and dev shops",
  },
};

/** Ordered cheapest first, for rendering a pricing table. */
export const MONITOR_PLAN_ORDER: MonitorPlan["key"][] = ["solo", "studio", "agency"];

/** The allowance for a plan key, or null if the key is not a sellable plan. */
export function urlLimitForPlan(plan: string): number | null {
  const found = MONITOR_PLANS[plan as MonitorPlan["key"]];
  return found ? found.urlLimit : null;
}

import { describe, it, expect } from "vitest";
import { resolveEntitlement, type BillingRow } from "./entitlements";
import { MONITOR_PLANS, MONITOR_PLAN_ORDER, urlLimitForPlan } from "./plans";

/**
 * This is the rule that decides whether a paying customer's site keeps being
 * watched. Both directions fail quietly: refuse wrongly and monitoring stops
 * with no error anyone sees until something is exploited; allow wrongly and
 * the product is free. It is pure so it can be tested without a database.
 */

const row = (over: Partial<BillingRow> = {}): BillingRow => ({
  plan: "studio",
  status: "active",
  urlLimit: 10,
  grandfathered: false,
  ...over,
});

describe("resolveEntitlement — while enforcement is off", () => {
  it("allows everything, which is exactly today's behaviour", () => {
    // The whole point of the flag: deploying this must change nothing.
    const e = resolveEntitlement(null, { enforced: false });
    expect(e.monitoringActive).toBe(true);
    expect(e.urlLimit).toBe(Number.POSITIVE_INFINITY);
    expect(e.reason).toBe("unenforced");
  });

  it("allows even a cancelled plan", () => {
    const e = resolveEntitlement(row({ status: "cancelled" }), { enforced: false });
    expect(e.monitoringActive).toBe(true);
  });
});

describe("resolveEntitlement — once enforcement is on", () => {
  const enforced = { enforced: true };

  it("allows an active plan, at its own stored limit", () => {
    const e = resolveEntitlement(row(), enforced);
    expect(e.monitoringActive).toBe(true);
    expect(e.urlLimit).toBe(10);
    expect(e.reason).toBe("active");
  });

  it("refuses a user with no plan at all", () => {
    const e = resolveEntitlement(null, enforced);
    expect(e.monitoringActive).toBe(false);
    expect(e.urlLimit).toBe(0);
    expect(e.reason).toBe("no_plan");
  });

  it("KEEPS MONITORING a past_due plan — Stripe is still retrying the card", () => {
    // The one most likely to be "tidied up" into a refusal by someone reading
    // quickly. Cutting a customer off on the first failed charge stops watching
    // their site over a card that usually succeeds on retry. Only the paused
    // state, set after retries are exhausted, actually stops scanning.
    const e = resolveEntitlement(row({ status: "past_due" }), enforced);
    expect(e.monitoringActive).toBe(true);
    expect(e.reason).toBe("grace_period");
  });

  it("stops monitoring a paused plan but remembers the limit", () => {
    const e = resolveEntitlement(row({ status: "paused" }), enforced);
    expect(e.monitoringActive).toBe(false);
    // Kept so the UI can say "your plan covered 10 sites" on the resubscribe
    // screen rather than showing zero.
    expect(e.urlLimit).toBe(10);
    expect(e.reason).toBe("paused");
  });

  it("stops monitoring a cancelled plan", () => {
    const e = resolveEntitlement(row({ status: "cancelled" }), enforced);
    expect(e.monitoringActive).toBe(false);
    expect(e.reason).toBe("cancelled");
  });
});

describe("resolveEntitlement — grandfathered accounts", () => {
  const enforced = { enforced: true };

  it("keeps monitoring a grandfathered account that never pays", () => {
    // The four people already monitoring for free when this shipped. They have
    // no Stripe subscription and no period end; the flag must not cut them off.
    const e = resolveEntitlement(
      row({ plan: "grandfathered", grandfathered: true, urlLimit: 2 }),
      enforced,
    );
    expect(e.monitoringActive).toBe(true);
    expect(e.urlLimit).toBe(2);
    expect(e.reason).toBe("grandfathered");
  });

  it("still honours a cancellation on a grandfathered account", () => {
    // Someone who asked to stop has stopped, however they got their allowance.
    const e = resolveEntitlement(
      row({ plan: "grandfathered", grandfathered: true, status: "cancelled" }),
      enforced,
    );
    expect(e.monitoringActive).toBe(false);
    expect(e.reason).toBe("cancelled");
  });
});

describe("MONITOR_PLANS", () => {
  it("prices every tier in whole cents, as Stripe requires", () => {
    for (const key of MONITOR_PLAN_ORDER) {
      const amount = MONITOR_PLANS[key].amountCents;
      expect(Number.isInteger(amount), key).toBe(true);
      expect(amount, key).toBeGreaterThan(0);
    }
  });

  it("gives a bigger plan a better per-URL rate, never a worse one", () => {
    // The same volume-discount property already pinned on the credit packs in
    // stripe.test.ts. A price edit that makes the larger tier worse value is
    // the mistake this catches, and it is invisible until a customer does the
    // arithmetic themselves.
    const perUrl = (k: (typeof MONITOR_PLAN_ORDER)[number]) =>
      MONITOR_PLANS[k].amountCents / MONITOR_PLANS[k].urlLimit;

    for (let i = 1; i < MONITOR_PLAN_ORDER.length; i++) {
      const bigger = MONITOR_PLAN_ORDER[i]!;
      const smaller = MONITOR_PLAN_ORDER[i - 1]!;
      expect(MONITOR_PLANS[bigger].urlLimit, `${bigger} should allow more URLs than ${smaller}`)
        .toBeGreaterThan(MONITOR_PLANS[smaller].urlLimit);
      expect(perUrl(bigger), `${bigger} costs more per URL than ${smaller}`)
        .toBeLessThanOrEqual(perUrl(smaller));
    }
  });

  it("resolves a limit for every sellable plan, and nothing else", () => {
    for (const key of MONITOR_PLAN_ORDER) {
      expect(urlLimitForPlan(key)).toBe(MONITOR_PLANS[key].urlLimit);
    }
    // "grandfathered" is a stored plan value but not a sellable tier — its
    // allowance comes off the row, never from this table.
    expect(urlLimitForPlan("grandfathered")).toBeNull();
    expect(urlLimitForPlan("enterprise")).toBeNull();
  });
});

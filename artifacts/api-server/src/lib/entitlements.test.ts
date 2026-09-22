import { describe, it, expect } from "vitest";
import { resolveEntitlement, type BillingRow } from "./entitlements";
import { MONITOR_PLANS, DEFAULT_PLAN, urlLimitForPlan, includedScansForPlan } from "./plans";
import { PRICE_MAP } from "./stripe";

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
  // The plan decided 2026-09-22. These numbers are what the pricing page
  // promises, so a change here is a change to what customers are sold — it
  // should fail a test and be made on purpose.
  it("sells one plan: $50/month, 3 sites, 5 scans a month", () => {
    expect(Object.keys(MONITOR_PLANS)).toEqual(["pro"]);
    expect(DEFAULT_PLAN.amountCents).toBe(5000);
    expect(DEFAULT_PLAN.urlLimit).toBe(3);
    expect(DEFAULT_PLAN.includedScans).toBe(5);
  });

  it("is priced in whole cents, as Stripe requires", () => {
    expect(Number.isInteger(DEFAULT_PLAN.amountCents)).toBe(true);
  });

  it("makes the included scans worth more than buying them as credits", () => {
    // The subscription is the way to save. If a pack ever beat it on the
    // scans alone, the pricing page would be arguing against itself.
    const perIncludedScan = DEFAULT_PLAN.amountCents / DEFAULT_PLAN.includedScans;
    expect(perIncludedScan).toBeLessThanOrEqual(PRICE_MAP["single"]!.amount);
  });

  it("resolves limits for the sold plan, and nothing else", () => {
    expect(urlLimitForPlan("pro")).toBe(3);
    expect(includedScansForPlan("pro")).toBe(5);
    // Designed-but-never-sold tiers and grandfathered rows get their allowance
    // from the row, never from this table.
    for (const k of ["solo", "studio", "agency", "grandfathered", "enterprise"]) {
      expect(urlLimitForPlan(k), k).toBeNull();
      expect(includedScansForPlan(k), k).toBe(0);
    }
  });
});

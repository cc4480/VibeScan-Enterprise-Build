import { describe, it, expect, afterEach } from "vitest";
import { resolveEntitlement, monitorExpiryApplies, freeMonitorSites, FREE_MONITOR_MIN_DAYS, rescanFloorDays, type BillingRow } from "./entitlements";
import { MONITOR_PLANS, DEFAULT_PLAN, SOLD_PLANS, planByKey, urlLimitForPlan, includedScansForPlan } from "./plans";
import { PRICE_MAP, CREDITS_MAP } from "./stripe";

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
  // The plans decided 2026-09-24. These numbers are what the pricing page
  // promises, so a change here is a change to what customers are sold — it
  // should fail a test and be made on purpose.
  it("sells two plans: Starter $19 (3 sites, 20 scans) and Pro $49 (5 sites, 100 scans)", () => {
    expect(SOLD_PLANS.map((p) => p.key)).toEqual(["starter", "pro"]);
    expect(MONITOR_PLANS.starter).toMatchObject({ amountCents: 1900, urlLimit: 3, includedScans: 20 });
    expect(MONITOR_PLANS.pro).toMatchObject({ amountCents: 4900, urlLimit: 5, includedScans: 100 });
    // A subscription started before there were two plans carried no plan key; it was Pro.
    expect(DEFAULT_PLAN.key).toBe("pro");
  });

  it("is priced in whole cents, as Stripe requires", () => {
    for (const p of SOLD_PLANS) expect(Number.isInteger(p.amountCents), p.key).toBe(true);
  });

  it("makes every plan's included scans cheaper than any credit pack", () => {
    // The subscription is the way to save. If a pack beat a plan on the scans
    // alone, the pricing page would be arguing against itself; the first
    // proposal for these prices did exactly that, and this is what caught it.
    const cheapestPack = Math.min(
      ...Object.keys(CREDITS_MAP).map((t) => PRICE_MAP[t]!.amount / CREDITS_MAP[t]!),
    );
    for (const p of SOLD_PLANS) {
      expect(p.amountCents / p.includedScans, p.key).toBeLessThan(cheapestPack);
    }
  });

  it("resolves limits for the sold plans, and nothing else", () => {
    expect(urlLimitForPlan("starter")).toBe(3);
    expect(includedScansForPlan("starter")).toBe(20);
    expect(urlLimitForPlan("pro")).toBe(5);
    expect(includedScansForPlan("pro")).toBe(100);
    expect(planByKey("pro")?.name).toBe("SecScan Pro");
    // Designed-but-never-sold tiers and grandfathered rows get their allowance
    // from the row, never from this table.
    for (const k of ["solo", "studio", "agency", "grandfathered", "enterprise", "", "constructor"]) {
      expect(urlLimitForPlan(k), k).toBeNull();
      expect(includedScansForPlan(k), k).toBe(0);
      expect(planByKey(k), k).toBeNull();
    }
  });
});

describe("monitorExpiryApplies — who ends a monitor", () => {
  afterEach(() => { delete process.env["MONITORING_REQUIRES_PLAN"]; });

  it("the 1-year expiresAt ends monitors while plans are not enforced", () => {
    delete process.env["MONITORING_REQUIRES_PLAN"];
    expect(monitorExpiryApplies()).toBe(true);
  });

  it("the plan ends them once enforced, so a monthly subscriber is not cut off in month 12", () => {
    process.env["MONITORING_REQUIRES_PLAN"] = "true";
    expect(monitorExpiryApplies()).toBe(false);
  });
});

describe("resolveEntitlement — the free site", () => {
  const enforced = { enforced: true, freeSites: 1 };

  it("lets an account with no billing row watch the free allowance", () => {
    const e = resolveEntitlement(null, enforced);
    expect(e.monitoringActive).toBe(true);
    expect(e.urlLimit).toBe(1);
    expect(e.reason).toBe("free");
    expect(e.plan).toBeNull();
  });

  it("keeps the old answer when no free allowance is passed", () => {
    // A caller that does not opt in must get "no plan, no monitoring" exactly as before.
    const e = resolveEntitlement(null, { enforced: true });
    expect(e.monitoringActive).toBe(false);
    expect(e.reason).toBe("no_plan");
  });

  it("gives no free site when the allowance is 0", () => {
    const e = resolveEntitlement(null, { enforced: true, freeSites: 0 });
    expect(e.monitoringActive).toBe(false);
    expect(e.reason).toBe("no_plan");
  });

  it("does not hand the free site to someone who cancelled or lapsed", () => {
    // A cancelled or paused row is a decision someone made, or a payment that failed.
    // It is not "never had a plan", and the free site is for people who never did.
    for (const status of ["cancelled", "paused"]) {
      const e = resolveEntitlement(row({ status }), enforced);
      expect(e.monitoringActive, status).toBe(false);
      expect(e.reason, status).toBe(status);
    }
  });

  it("changes nothing for a paying or grandfathered account", () => {
    expect(resolveEntitlement(row(), enforced).urlLimit).toBe(10);
    expect(resolveEntitlement(row({ grandfathered: true, plan: "grandfathered", urlLimit: 2 }), enforced).urlLimit).toBe(2);
  });

  it("changes nothing while enforcement is off", () => {
    const e = resolveEntitlement(null, { enforced: false, freeSites: 1 });
    expect(e.reason).toBe("unenforced");
    expect(e.urlLimit).toBe(Number.POSITIVE_INFINITY);
  });
});

describe("freeMonitorSites", () => {
  afterEach(() => { delete process.env["FREE_MONITOR_SITES"]; });

  it("defaults to one site", () => {
    delete process.env["FREE_MONITOR_SITES"];
    expect(freeMonitorSites()).toBe(1);
  });

  it("reads the operator's setting, including 0 to turn the free site off", () => {
    process.env["FREE_MONITOR_SITES"] = "0";
    expect(freeMonitorSites()).toBe(0);
    process.env["FREE_MONITOR_SITES"] = "2";
    expect(freeMonitorSites()).toBe(2);
  });

  it("falls back to one for a value that is not a whole number", () => {
    // A typo must not silently grant five sites or none.
    for (const bad of ["", " ", "abc", "-1", "1.5", "NaN"]) {
      process.env["FREE_MONITOR_SITES"] = bad;
      expect(freeMonitorSites(), JSON.stringify(bad)).toBe(1);
    }
  });

  it("holds a free site to weekly rescans", () => {
    expect(FREE_MONITOR_MIN_DAYS).toBe(7);
  });
});

describe("rescanFloorDays", () => {
  it("holds an account with no live plan to weekly once plans are enforced", () => {
    expect(rescanFloorDays({ enforced: true, hasLivePlan: false })).toBe(FREE_MONITOR_MIN_DAYS);
  });

  it("leaves a paying account on the grade-based cadence", () => {
    expect(rescanFloorDays({ enforced: true, hasLivePlan: true })).toBe(0);
  });

  it("changes nothing while enforcement is off, whoever the account is", () => {
    expect(rescanFloorDays({ enforced: false, hasLivePlan: false })).toBe(0);
    expect(rescanFloorDays({ enforced: false, hasLivePlan: true })).toBe(0);
  });
});

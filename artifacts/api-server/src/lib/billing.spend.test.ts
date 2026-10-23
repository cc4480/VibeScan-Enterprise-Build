import { m, subscriptionCompleted, invoicePaid, suite, billingHarness } from "./billing.testkit";
import { it, expect } from "vitest";

/** Billing against a real Postgres — see billing.testkit.ts for how to run it. */



suite("billing (real Postgres)", () => {
  const { balance, plan, setAllowance, insertScan } = billingHarness();

  // ── One spend order, one notion of "has a plan" ───────────────────────────
  it("charges in one order — free, then plan scans, then credits — and refuses when all are gone", async () => {
    const trial = await import("./freeTrial");
    await m.webhook.processStripeEvent(subscriptionCompleted("u20", "sub_H"));
    await m.webhook.processStripeEvent(invoicePaid("sub_H", "u20"));
    await setAllowance("u20", 5);
    await m.billing.addCredits(m.db.db, "u20", 1);

    const seen: string[] = [];
    for (let i = 0; i < 10; i++) {
      const paid = await m.billing.chargeScan("u20");
      seen.push(String(paid));
      // A free charge takes nothing now; the scan row it creates is what counts.
      if (paid === "free") await insertScan("u20", "free");
    }
    expect(seen).toEqual(["free", "free", "free", "included", "included", "included", "included", "included", "credit", "null"]);
    expect(await trial.trialScansUsedBy("u20")).toBe(3);
  });

  it("counts a monitor scan paid with a free scan toward the trial, but never the scheduler's own", async () => {
    const trial = await import("./freeTrial");
    const { db, scansTable } = m.db;
    const add = (paidWith: "free" | null) =>
      db.insert(scansTable).values({ userId: "u21", userEmail: "", targetUrl: "https://example.com", tier: "deep", status: "complete", origin: "monitor", paidWith });
    await add(null); await add(null); await add(null);   // automatic rescans
    expect(await trial.trialScansUsedBy("u21")).toBe(0);
    await add("free");                                     // a free user's "Scan now"
    expect(await trial.trialScansUsedBy("u21")).toBe(1);
  });

  it("treats active, past-due and grandfathered plans as live — and paused, cancelled or none as not", async () => {
    const { db, billingSubscriptionsTable } = m.db;
    const row = (userId: string, status: "active" | "past_due" | "paused" | "cancelled", grandfathered = false) =>
      db.insert(billingSubscriptionsTable).values({ userId, plan: grandfathered ? "grandfathered" : "pro", status, urlLimit: 3, grandfathered });
    await row("p-active", "active"); await row("p-due", "past_due"); await row("p-paused", "paused");
    await row("p-cancel", "cancelled"); await row("p-gf", "active", true); await row("p-gf-cancel", "cancelled", true);
    const live = async (u: string) => m.billing.hasLivePlan(u);
    expect(await live("p-active")).toBe(true);
    expect(await live("p-due")).toBe(true);
    expect(await live("p-gf")).toBe(true);
    expect(await live("p-paused")).toBe(false);
    expect(await live("p-cancel")).toBe(false);
    expect(await live("p-gf-cancel")).toBe(false);
    expect(await live("no-plan-at-all")).toBe(false);
  });
});

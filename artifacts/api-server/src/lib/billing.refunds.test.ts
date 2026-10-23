import { m, subscriptionCompleted, invoicePaid, subscriptionEvent, suite, PRO, billingHarness } from "./billing.testkit";
import { it, expect } from "vitest";

/** Billing against a real Postgres — see billing.testkit.ts for how to run it. */



suite("billing (real Postgres)", () => {
  const { balance, plan, setAllowance, insertScan } = billingHarness();

  // ── Bug 4: failed scans ────────────────────────────────────────────────────
  it("refunds a failed scan's credit exactly once, however many times failure is handled", async () => {
    const scanId = await insertScan("u9", "credit");
    const results = await Promise.all(Array.from({ length: 6 }, () => m.billing.refundFailedScan(scanId)));
    expect(results.filter((r) => r === "credit")).toHaveLength(1);
    expect(await balance("u9")).toBe(1);
  });

  it("returns a failed scan to the subscription it came from, not as a credit", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u10", "sub_F"));
    await m.webhook.processStripeEvent(invoicePaid("sub_F", "u10"));
    await m.billing.spendIncludedScan("u10");
    const scanId = await insertScan("u10", "included");

    expect(await m.billing.refundFailedScan(scanId)).toBe("included");
    expect((await plan("u10"))?.includedScansRemaining).toBe(PRO.includedScans);
    expect(await balance("u10")).toBe(0);
  });

  it("gives nothing back for a failed free-trial scan", async () => {
    const scanId = await insertScan("u11", "free");
    expect(await m.billing.refundFailedScan(scanId)).toBeNull();
    expect(await balance("u11")).toBe(0);
  });

  it("returns a failed scan as a CREDIT when the plan it came from has since been cancelled", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u12", "sub_G"));
    await m.webhook.processStripeEvent(invoicePaid("sub_G", "u12"));
    await m.billing.spendIncludedScan("u12");
    const scanId = await insertScan("u12", "included");
    await m.webhook.processStripeEvent(subscriptionEvent("customer.subscription.deleted", "sub_G", "canceled"));

    expect(await m.billing.refundFailedScan(scanId)).toBe("included");
    // Not lost into a cancelled plan: returned as something they can still use.
    expect(await balance("u12")).toBe(1);
  });

  // ── Scans that never finish ────────────────────────────────────────────────
  async function insertScanAt(userId: string, status: string, paidWith: "free" | "included" | "credit", hoursAgo: number) {
    const { db, scansTable } = m.db;
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId, userEmail: "", targetUrl: "https://example.com", tier: "deep",
        status: status as never, paidWith, createdAt: new Date(Date.now() - hoursAgo * 3600_000),
        // A stored login, as an authenticated scan would hold while it runs.
        credentialsEncrypted: "enc-primary", secondaryCredentialsEncrypted: "enc-secondary",
      })
      .returning();
    return scan!.id;
  }
  const statusOf = async (id: string) => {
    const { db, scansTable } = m.db;
    const { eq } = await import("drizzle-orm");
    const [row] = await db.select({ status: scansTable.status }).from(scansTable).where(eq(scansTable.id, id));
    return row?.status;
  };

  it("fails and refunds a paid scan stuck for hours, and leaves live and finished ones alone", async () => {
    const stuckPaid = await insertScanAt("u13", "scanning", "credit", 9);
    const stuckFree = await insertScanAt("u13", "queued", "free", 9);
    const recent = await insertScanAt("u13", "scanning", "credit", 1);
    const done = await insertScanAt("u13", "complete", "credit", 20);

    const first = await m.billing.reapStuckScans();
    expect(first).toEqual({ failed: 2, refunded: 1 });
    expect(await statusOf(stuckPaid)).toBe("failed");
    expect(await statusOf(stuckFree)).toBe("failed");
    expect(await statusOf(recent)).toBe("scanning"); // slow, not dead
    expect(await statusOf(done)).toBe("complete");
    expect(await balance("u13")).toBe(1);

    // A dead scan has ended, so its stored logins are gone; a live one still needs them.
    const creds = async (id: string) => {
      const { db, scansTable } = m.db;
      const { eq } = await import("drizzle-orm");
      const [row] = await db.select({ a: scansTable.credentialsEncrypted, b: scansTable.secondaryCredentialsEncrypted }).from(scansTable).where(eq(scansTable.id, id));
      return row;
    };
    expect(await creds(stuckPaid)).toEqual({ a: null, b: null });
    expect(await creds(stuckFree)).toEqual({ a: null, b: null });
    expect(await creds(recent)).toEqual({ a: "enc-primary", b: "enc-secondary" });

    // Running it again refunds nothing twice.
    expect(await m.billing.reapStuckScans()).toEqual({ failed: 0, refunded: 0 });
    expect(await balance("u13")).toBe(1);
  });
});

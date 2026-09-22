/**
 * Billing against a REAL Postgres.
 *
 * Every rule these pin is a database guarantee — a primary-key collision, an
 * atomic upsert, a row lock — and a mocked db would happily "prove" all of them
 * while the real SQL did something else. So this runs only when a disposable
 * database is supplied, and skips otherwise:
 *
 *   docker run -d --rm --name billing-test-pg -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_DB=billing -p 5440:5432 postgres:16
 *   BILLING_TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:5440/billing \
 *     npx vitest run src/lib/billing.integration.test.ts
 *
 * NEVER point it at a database whose data matters: it truncates the billing
 * tables between tests.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;

// Set before @workspace/db is imported: it builds its pool from DATABASE_URL
// at import time, and vitest.config pins a placeholder.
if (URL_) process.env["DATABASE_URL"] = URL_;

type Mod = {
  db: typeof import("@workspace/db");
  billing: typeof import("./billing");
  webhook: typeof import("../routes/stripe");
};
let m: Mod;

let seq = 0;
const evId = () => `evt_test_${Date.now()}_${++seq}`;

/** A credit-pack checkout, shaped like Stripe's. */
function packCompleted(userId: string, tier: string, paymentStatus: "paid" | "unpaid", id = evId()) {
  return {
    id,
    type: "checkout.session.completed",
    data: {
      object: {
        mode: "payment",
        payment_status: paymentStatus,
        metadata: { type: "credits", user_id: userId, tier },
        customer_details: null,
        customer_email: null,
        amount_total: 5000,
      },
    },
  } as never;
}

function subscriptionCompleted(userId: string, subId: string) {
  return {
    id: evId(),
    type: "checkout.session.completed",
    data: {
      object: {
        mode: "subscription",
        payment_status: "paid",
        metadata: { type: "subscription", user_id: userId },
        subscription: subId,
        customer: "cus_test",
      },
    },
  } as never;
}

function invoicePaid(subId: string, userId: string | null, id = evId()) {
  return {
    id,
    type: "invoice.paid",
    data: {
      object: {
        customer: "cus_test",
        parent: { subscription_details: { subscription: subId, metadata: userId ? { user_id: userId } : {} } },
        lines: { data: [{ period: { end: Math.floor(Date.now() / 1000) + 30 * 86400 } }] },
      },
    },
  } as never;
}

function subscriptionEvent(type: "customer.subscription.updated" | "customer.subscription.deleted", subId: string, status: string) {
  return {
    id: evId(),
    type,
    data: { object: { id: subId, status, items: { data: [{ current_period_end: Math.floor(Date.now() / 1000) + 86400 }] } } },
  } as never;
}

suite("billing (real Postgres)", () => {
  beforeAll(async () => {
    const dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    m = { db: dbMod, billing: await import("./billing"), webhook: await import("../routes/stripe") };
  }, 60_000);

  beforeEach(async () => {
    const { db } = m.db;
    const { sql } = await import("drizzle-orm");
    await db.execute(sql`TRUNCATE stripe_events, credits, billing_subscriptions, scans CASCADE`);
    // TRUNCATE takes an exclusive lock; under a loaded machine the default 10s
    // hook limit is too tight for it, and a timeout here is not a billing bug.
  }, 30_000);

  afterAll(async () => {
    await m?.db.pool?.end?.();
  });

  const balance = async (userId: string) => {
    const { db, creditsTable } = m.db;
    const { eq } = await import("drizzle-orm");
    const [row] = await db.select().from(creditsTable).where(eq(creditsTable.userId, userId));
    return row?.balance ?? 0;
  };
  const plan = async (userId: string) => {
    const { db, billingSubscriptionsTable } = m.db;
    const { eq } = await import("drizzle-orm");
    const [row] = await db.select().from(billingSubscriptionsTable).where(eq(billingSubscriptionsTable.userId, userId));
    return row ?? null;
  };

  // ── Bug 1: duplicate delivery ──────────────────────────────────────────────
  it("credits a pack exactly once, however many times Stripe delivers it", async () => {
    const event = packCompleted("u1", "pack_5", "paid");
    const first = await m.webhook.processStripeEvent(event);
    const again = await m.webhook.processStripeEvent(event);
    const third = await m.webhook.processStripeEvent(event);

    expect(first.duplicate).toBe(false);
    expect(again.duplicate).toBe(true);
    expect(third.duplicate).toBe(true);
    expect(await balance("u1")).toBe(5); // was 15 before the ledger
  });

  it("applies each duplicate once even when the deliveries race each other", async () => {
    const event = packCompleted("u1", "pack_20", "paid");
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => m.webhook.processStripeEvent(event)));
    const applied = results.filter((r) => r.status === "fulfilled" && !r.value.duplicate).length;
    expect(applied).toBe(1);
    expect(await balance("u1")).toBe(20);
  });

  it("rolls the ledger back with the effect, so a failed delivery's retry still applies", async () => {
    const { db } = m.db;
    const id = evId();
    await expect(
      db.transaction(async (tx) => {
        await m.billing.claimStripeEvent(tx, { id, type: "checkout.session.completed" });
        throw new Error("crash after claiming, before applying");
      }),
    ).rejects.toThrow();

    const retry = await m.webhook.processStripeEvent(packCompleted("u1", "pack_5", "paid", id));
    expect(retry.duplicate).toBe(false);
    expect(await balance("u1")).toBe(5);
  });

  // ── Bug 2: lost updates ────────────────────────────────────────────────────
  it("loses no credits when purchases and spends land at the same time", async () => {
    await m.billing.addCredits(m.db.db, "u2", 10);
    const { spendOneCredit } = await import("./credits");

    await Promise.all([
      ...Array.from({ length: 6 }, () => m.webhook.processStripeEvent(packCompleted("u2", "single", "paid"))),
      ...Array.from({ length: 4 }, () => spendOneCredit("u2")),
    ]);
    // 10 + 6 bought - 4 spent. Read-then-write lost some of these.
    expect(await balance("u2")).toBe(12);
  });

  // ── Bug 3: money not yet taken ─────────────────────────────────────────────
  it("grants nothing for an unpaid checkout, then grants when the payment clears", async () => {
    const r = await m.webhook.processStripeEvent(packCompleted("u3", "pack_5", "unpaid"));
    expect(r.applied).toMatch(/deferred/);
    expect(await balance("u3")).toBe(0);

    const cleared = { ...(packCompleted("u3", "pack_5", "paid") as object), type: "checkout.session.async_payment_succeeded" };
    await m.webhook.processStripeEvent(cleared as never);
    expect(await balance("u3")).toBe(5);
  });

  it("ignores a pack that is not sold (a retired per-scan tier grants nothing)", async () => {
    await m.webhook.processStripeEvent(packCompleted("u3", "deep", "paid"));
    expect(await balance("u3")).toBe(0);
  });

  // ── The subscription ──────────────────────────────────────────────────────
  it("starts the plan on checkout, but grants scans only when the invoice is paid", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u4", "sub_A"));
    let row = await plan("u4");
    expect(row?.plan).toBe("pro");
    expect(row?.urlLimit).toBe(3);
    expect(row?.includedScansRemaining).toBe(0);

    await m.webhook.processStripeEvent(invoicePaid("sub_A", "u4"));
    row = await plan("u4");
    expect(row?.includedScansRemaining).toBe(5);
    expect(row?.currentPeriodEnd).not.toBeNull();
  });

  it("works when Stripe delivers invoice.paid BEFORE checkout.session.completed", async () => {
    await m.webhook.processStripeEvent(invoicePaid("sub_B", "u5"));
    expect((await plan("u5"))?.includedScansRemaining).toBe(5);

    await m.webhook.processStripeEvent(subscriptionCompleted("u5", "sub_B"));
    // Checkout arriving late must not wipe the allowance the invoice granted.
    expect((await plan("u5"))?.includedScansRemaining).toBe(5);
  });

  it("does not roll unused scans over, and a redelivered invoice cannot stack them", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u6", "sub_C"));
    const march = invoicePaid("sub_C", "u6");
    await m.webhook.processStripeEvent(march);
    await m.billing.spendIncludedScan("u6");
    await m.billing.spendIncludedScan("u6");
    expect((await plan("u6"))?.includedScansRemaining).toBe(3);

    await m.webhook.processStripeEvent(march); // redelivery
    expect((await plan("u6"))?.includedScansRemaining).toBe(3);

    await m.webhook.processStripeEvent(invoicePaid("sub_C", "u6")); // next month
    expect((await plan("u6"))?.includedScansRemaining).toBe(5); // reset, not 8
  });

  it("never lets two concurrent scans both take the last included scan", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u7", "sub_D"));
    await m.webhook.processStripeEvent(invoicePaid("sub_D", "u7"));
    const spends = await Promise.all(Array.from({ length: 12 }, () => m.billing.spendIncludedScan("u7")));
    expect(spends.filter((r) => r !== null)).toHaveLength(5);
    expect((await plan("u7"))?.includedScansRemaining).toBe(0);
  });

  it("keeps a past-due customer scanning, stops a paused one, and ends a cancelled one", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u8", "sub_E"));
    await m.webhook.processStripeEvent(invoicePaid("sub_E", "u8"));

    await m.webhook.processStripeEvent(subscriptionEvent("customer.subscription.updated", "sub_E", "past_due"));
    expect((await plan("u8"))?.status).toBe("past_due");
    expect(await m.billing.spendIncludedScan("u8")).not.toBeNull(); // card retrying: still served

    await m.webhook.processStripeEvent(subscriptionEvent("customer.subscription.updated", "sub_E", "unpaid"));
    expect((await plan("u8"))?.status).toBe("paused");
    expect(await m.billing.spendIncludedScan("u8")).toBeNull();

    await m.webhook.processStripeEvent(subscriptionEvent("customer.subscription.deleted", "sub_E", "canceled"));
    const row = await plan("u8");
    expect(row?.status).toBe("cancelled");
    expect(row?.includedScansRemaining).toBe(0);
  });

  // ── Bug 4: failed scans ────────────────────────────────────────────────────
  async function insertScan(userId: string, paidWith: "free" | "included" | "credit") {
    const { db, scansTable } = m.db;
    const [scan] = await db
      .insert(scansTable)
      .values({ userId, userEmail: "", targetUrl: "https://example.com", tier: "deep", status: "failed", paidWith })
      .returning();
    return scan!.id;
  }

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
    expect((await plan("u10"))?.includedScansRemaining).toBe(5);
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

    // Running it again refunds nothing twice.
    expect(await m.billing.reapStuckScans()).toEqual({ failed: 0, refunded: 0 });
    expect(await balance("u13")).toBe(1);
  });
});

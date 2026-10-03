import { describe, beforeAll, beforeEach, afterAll, it } from "vitest";
import { MONITOR_PLANS, type PlanKey } from "./plans";

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



// The counted plan most of these tests exercise. Pro stopped being sold on 2026-10-03 but is
// still a known plan, so a row carrying it must keep working; the builders below name it
// explicitly because a subscription with NO plan metadata now gets the unlimited plan.
export const PRO = MONITOR_PLANS.pro;
export const UNLIMITED = MONITOR_PLANS.unlimited;

export const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
export const suite = URL_ ? describe : describe.skip;

// Set before @workspace/db is imported: it builds its pool from DATABASE_URL
// at import time, and vitest.config pins a placeholder.
if (URL_) process.env["DATABASE_URL"] = URL_;

export type Mod = {
  db: typeof import("@workspace/db");
  billing: typeof import("./billing");
  webhook: typeof import("../routes/stripe");
};
// One object for every test file's `m`: filled in by the harness's beforeAll, so test bodies read `m.webhook` as before.
export const m = {} as Mod;

export let seq = 0;
export const evId = () => `evt_test_${Date.now()}_${++seq}`;

/** A credit-pack checkout, shaped like Stripe's. */
export function packCompleted(userId: string, tier: string, paymentStatus: "paid" | "unpaid", id = evId()) {
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

export function subscriptionCompleted(userId: string, subId: string, plan: PlanKey | null = "pro") {
  return {
    id: evId(),
    type: "checkout.session.completed",
    data: {
      object: {
        mode: "subscription",
        payment_status: "paid",
        metadata: { type: "subscription", user_id: userId, ...(plan ? { plan } : {}) },
        subscription: subId,
        customer: "cus_test",
      },
    },
  } as never;
}

export function invoicePaid(subId: string, userId: string | null, id = evId(), plan: PlanKey | null = "pro") {
  return {
    id,
    type: "invoice.paid",
    data: {
      object: {
        customer: "cus_test",
        parent: { subscription_details: { subscription: subId, metadata: userId ? { user_id: userId, ...(plan ? { plan } : {}) } : {} } },
        lines: { data: [{ period: { end: Math.floor(Date.now() / 1000) + 30 * 86400 } }] },
      },
    },
  } as never;
}

export function subscriptionEvent(type: "customer.subscription.updated" | "customer.subscription.deleted", subId: string, status: string) {
  return {
    id: evId(),
    type,
    data: { object: { id: subId, status, items: { data: [{ current_period_end: Math.floor(Date.now() / 1000) + 86400 }] } } },
  } as never;
}

/** Registers the database hooks for one suite and returns the helpers that read the tables. Call it first inside `suite(...)`. */
export function billingHarness() {
  beforeAll(async () => {
    const dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    Object.assign(m, { db: dbMod, billing: await import("./billing"), webhook: await import("../routes/stripe") });
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

  /** Pin the remaining allowance where a test is about spending, not about the plan's size. */
  const setAllowance = async (userId: string, n: number) => {
    const { db, billingSubscriptionsTable } = m.db;
    const { eq } = await import("drizzle-orm");
    await db.update(billingSubscriptionsTable).set({ includedScansRemaining: n }).where(eq(billingSubscriptionsTable.userId, userId));
  };

  async function insertScan(userId: string, paidWith: "free" | "included" | "credit") {
    const { db, scansTable } = m.db;
    const [scan] = await db
      .insert(scansTable)
      .values({ userId, userEmail: "", targetUrl: "https://example.com", tier: "deep", status: "failed", paidWith })
      .returning();
    return scan!.id;
  }

  return { balance, plan, setAllowance, insertScan };
}

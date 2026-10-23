/**
 * The second-subscription guard, against a REAL Postgres (see
 * billing.integration.test.ts for how to start one; skipped without
 * BILLING_TEST_DATABASE_URL, and it truncates the billing tables).
 *
 * Found by paying two checkout links for one account against real Stripe test
 * mode: both sessions were created before either was paid, so the "already
 * subscribed" check never fired, both charged, and the second overwrote the
 * first on the plan row. The customer kept being billed for a subscription the
 * database had forgotten.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { MONITOR_PLANS } from "./plans";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

type Mod = { db: typeof import("@workspace/db"); webhook: typeof import("../routes/stripe") };
let m: Mod;
let seq = 0;
const evId = () => `evt_sub_${Date.now()}_${++seq}`;

const checkoutDone = (userId: string, subId: string, planKey: string) =>
  ({
    id: evId(),
    type: "checkout.session.completed",
    data: {
      object: {
        mode: "subscription",
        payment_status: "paid",
        metadata: { type: "subscription", user_id: userId, plan: planKey },
        subscription: subId,
        customer: `cus_${subId}`,
      },
    },
  }) as never;

const invoicePaid = (subId: string, userId: string, planKey: string) =>
  ({
    id: evId(),
    type: "invoice.paid",
    data: {
      object: {
        customer: `cus_${subId}`,
        parent: { subscription_details: { subscription: subId, metadata: { user_id: userId, plan: planKey } } },
        lines: { data: [{ period: { end: Math.floor(Date.now() / 1000) + 30 * 86400 } }] },
      },
    },
  }) as never;

suite("second subscription for one account (real Postgres)", () => {
  beforeAll(async () => {
    const dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    m = { db: dbMod, webhook: await import("../routes/stripe") };
  }, 60_000);

  beforeEach(async () => {
    const { sql } = await import("drizzle-orm");
    await m.db.db.execute(sql`TRUNCATE stripe_events, credits, billing_subscriptions, scans CASCADE`);
  }, 30_000);

  afterAll(async () => {
    await m?.db.pool?.end?.();
  });

  const row = async (userId: string) => {
    const { db, billingSubscriptionsTable } = m.db;
    const { eq } = await import("drizzle-orm");
    const [r] = await db.select().from(billingSubscriptionsTable).where(eq(billingSubscriptionsTable.userId, userId));
    return r ?? null;
  };

  const subscribe = async (userId: string, subId: string, planKey: "starter" | "pro") => {
    await m.webhook.processStripeEvent(checkoutDone(userId, subId, planKey));
    await m.webhook.processStripeEvent(invoicePaid(subId, userId, planKey));
  };

  it("keeps the first plan, and queues the second subscription to be cancelled and refunded", async () => {
    await subscribe("d1", "sub_first", "starter");

    const second = await m.webhook.processStripeEvent(checkoutDone("d1", "sub_second", "pro"));
    expect(second.applied).toMatch(/duplicate subscription sub_second/);
    expect(second.after).toHaveLength(1);

    const r = await row("d1");
    expect(r?.stripeSubscriptionId).toBe("sub_first");
    expect(r?.plan).toBe("starter");
    expect(r?.urlLimit).toBe(MONITOR_PLANS.starter.urlLimit);
  });

  it("does not hand out the duplicate's scans when its invoice is paid", async () => {
    await subscribe("d2", "sub_first", "starter");
    const before = (await row("d2"))?.includedScansRemaining;

    const paid = await m.webhook.processStripeEvent(invoicePaid("sub_second", "d2", "pro"));
    expect(paid.applied).toMatch(/duplicate subscription sub_second/);
    expect(paid.after).toHaveLength(1);
    expect((await row("d2"))?.includedScansRemaining).toBe(before);
    expect((await row("d2"))?.stripeSubscriptionId).toBe("sub_first");
  });

  it("works whichever order Stripe delivers the duplicate's events in", async () => {
    await subscribe("d3", "sub_first", "pro");
    await m.webhook.processStripeEvent(invoicePaid("sub_second", "d3", "starter"));
    await m.webhook.processStripeEvent(checkoutDone("d3", "sub_second", "starter"));
    expect((await row("d3"))?.stripeSubscriptionId).toBe("sub_first");
    expect((await row("d3"))?.plan).toBe("pro");
  });

  it("queues the cancel and refund once per event, not once per redelivery", async () => {
    await subscribe("d4", "sub_first", "starter");
    const event = checkoutDone("d4", "sub_second", "pro");
    const first = await m.webhook.processStripeEvent(event);
    const again = await m.webhook.processStripeEvent(event);
    expect(first.after).toHaveLength(1);
    expect(again.duplicate).toBe(true);
    expect(again.after).toHaveLength(0);
  });

  it("lets someone whose plan was cancelled subscribe again", async () => {
    await subscribe("d5", "sub_old", "starter");
    await m.webhook.processStripeEvent({
      id: evId(),
      type: "customer.subscription.deleted",
      data: { object: { id: "sub_old", status: "canceled", items: { data: [] } } },
    } as never);
    expect((await row("d5"))?.status).toBe("cancelled");

    const again = await m.webhook.processStripeEvent(checkoutDone("d5", "sub_new", "pro"));
    expect(again.after).toHaveLength(0);
    const r = await row("d5");
    expect(r?.stripeSubscriptionId).toBe("sub_new");
    expect(r?.plan).toBe("pro");
    expect(r?.status).toBe("active");
  });

  it("ignores an invoice.paid retry that arrives after the subscription was cancelled", async () => {
    await subscribe("d6", "sub_gone", "starter");
    await m.webhook.processStripeEvent({
      id: evId(),
      type: "customer.subscription.deleted",
      data: { object: { id: "sub_gone", status: "canceled", items: { data: [] } } },
    } as never);

    const late = await m.webhook.processStripeEvent(invoicePaid("sub_gone", "d6", "starter"));
    expect(late.applied).toMatch(/cancelled subscription sub_gone: ignored/);
    const r = await row("d6");
    expect(r?.status).toBe("cancelled");
    expect(r?.includedScansRemaining).toBe(0);
  });

  it("ignores a subscription.updated that arrives after the subscription was deleted", async () => {
    await subscribe("d7", "sub_gone2", "starter");
    await m.webhook.processStripeEvent({
      id: evId(),
      type: "customer.subscription.deleted",
      data: { object: { id: "sub_gone2", status: "canceled", items: { data: [] } } },
    } as never);
    await m.webhook.processStripeEvent({
      id: evId(),
      type: "customer.subscription.updated",
      data: { object: { id: "sub_gone2", status: "active", items: { data: [] } } },
    } as never);
    expect((await row("d7"))?.status).toBe("cancelled");
  });

  it("lets a grandfathered account with no Stripe subscription buy a plan", async () => {
    const { db, billingSubscriptionsTable } = m.db;
    await db.insert(billingSubscriptionsTable).values({ userId: "d6", plan: "grandfathered", status: "active", urlLimit: 3, grandfathered: true });
    const bought = await m.webhook.processStripeEvent(checkoutDone("d6", "sub_first", "starter"));
    expect(bought.after).toHaveLength(0);
    expect((await row("d6"))?.stripeSubscriptionId).toBe("sub_first");
  });
});

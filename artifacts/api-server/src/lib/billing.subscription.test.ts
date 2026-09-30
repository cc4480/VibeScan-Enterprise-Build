import { m, subscriptionCompleted, invoicePaid, subscriptionEvent, suite, PRO, billingHarness } from "./billing.testkit";
import { it, expect } from "vitest";

/** Billing against a real Postgres — see billing.testkit.ts for how to run it. */



suite("billing (real Postgres)", () => {
  const { balance, plan, setAllowance, insertScan } = billingHarness();

  // ── The subscription ──────────────────────────────────────────────────────
  it("starts the plan on checkout, but grants scans only when the invoice is paid", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u4", "sub_A"));
    let row = await plan("u4");
    expect(row?.plan).toBe("pro");
    expect(row?.urlLimit).toBe(PRO.urlLimit);
    expect(row?.includedScansRemaining).toBe(0);

    await m.webhook.processStripeEvent(invoicePaid("sub_A", "u4"));
    row = await plan("u4");
    expect(row?.includedScansRemaining).toBe(PRO.includedScans);
    expect(row?.currentPeriodEnd).not.toBeNull();
  });

  it("works when Stripe delivers invoice.paid BEFORE checkout.session.completed", async () => {
    await m.webhook.processStripeEvent(invoicePaid("sub_B", "u5"));
    expect((await plan("u5"))?.includedScansRemaining).toBe(PRO.includedScans);

    await m.webhook.processStripeEvent(subscriptionCompleted("u5", "sub_B"));
    // Checkout arriving late must not wipe the allowance the invoice granted.
    expect((await plan("u5"))?.includedScansRemaining).toBe(PRO.includedScans);
  });

  it("does not roll unused scans over, and a redelivered invoice cannot stack them", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u6", "sub_C"));
    const march = invoicePaid("sub_C", "u6");
    await m.webhook.processStripeEvent(march);
    await m.billing.spendIncludedScan("u6");
    await m.billing.spendIncludedScan("u6");
    expect((await plan("u6"))?.includedScansRemaining).toBe(PRO.includedScans - 2);

    await m.webhook.processStripeEvent(march); // redelivery
    expect((await plan("u6"))?.includedScansRemaining).toBe(PRO.includedScans - 2);

    await m.webhook.processStripeEvent(invoicePaid("sub_C", "u6")); // next month
    expect((await plan("u6"))?.includedScansRemaining).toBe(PRO.includedScans); // reset, not stacked
  });

  it("never lets two concurrent scans both take the last included scan", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("u7", "sub_D"));
    await m.webhook.processStripeEvent(invoicePaid("sub_D", "u7"));
    await setAllowance("u7", 5);
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
});

import { m, subscriptionCompleted, invoicePaid, subscriptionEvent, suite, UNLIMITED, billingHarness } from "./billing.testkit";
import { it, expect } from "vitest";

/**
 * The unlimited plan (SecScan Unlimited, 2026-10-03), against a real Postgres: see
 * billing.testkit.ts for how to run it. It keeps no scan counter, so what these pin is
 * the ABSENCE of bookkeeping that a counted plan needs: a charge takes nothing, a refund
 * puts nothing back, and a refund must never turn into a credit the person did not pay for.
 */
suite("unlimited plan (real Postgres)", () => {
  const { balance, plan, insertScan } = billingHarness();

  const subscribe = async (userId: string, subId: string) => {
    await m.webhook.processStripeEvent(subscriptionCompleted(userId, subId, "unlimited"));
    await m.webhook.processStripeEvent(invoicePaid(subId, userId, undefined, "unlimited"));
  };

  it("starts on the sold plan with its site limit, and grants no counter", async () => {
    await subscribe("un1", "sub_U1");
    const row = await plan("un1");
    expect(row?.plan).toBe("unlimited");
    expect(row?.urlLimit).toBe(UNLIMITED.urlLimit);
    expect(row?.includedScansRemaining).toBe(0);
  });

  it("is the plan a subscription with no plan metadata gets, from either event order", async () => {
    // A client written before plans had keys, or metadata that went missing, must land on
    // the one plan on sale and not on a legacy counted plan.
    await m.webhook.processStripeEvent(subscriptionCompleted("un2", "sub_U2", null));
    await m.webhook.processStripeEvent(invoicePaid("sub_U2", "un2", undefined, null));
    expect((await plan("un2"))?.plan).toBe("unlimited");

    await m.webhook.processStripeEvent(invoicePaid("sub_U3", "un3", undefined, null)); // invoice first
    expect((await plan("un3"))?.plan).toBe("unlimited");
  });

  it("charges every scan to the plan, without spending the free scans, a counter or credits", async () => {
    await subscribe("un4", "sub_U4");
    await m.billing.addCredits(m.db.db, "un4", 2);

    const paid: (string | null)[] = [];
    for (let i = 0; i < 50; i++) paid.push(await m.billing.chargeScan("un4"));

    expect(new Set(paid)).toEqual(new Set(["included"]));
    expect((await plan("un4"))?.includedScansRemaining).toBe(0);
    expect(await balance("un4")).toBe(2); // credits untouched
  });

  it("keeps scanning through a past-due card, and stops scanning once paused or cancelled", async () => {
    await subscribe("un5", "sub_U5");
    await m.webhook.processStripeEvent(subscriptionEvent("customer.subscription.updated", "sub_U5", "past_due"));
    expect(await m.billing.chargeScan("un5")).toBe("included"); // Stripe is still retrying the card

    await m.webhook.processStripeEvent(subscriptionEvent("customer.subscription.updated", "sub_U5", "unpaid"));
    // Paused: the plan no longer pays, so the person is back on the free scans.
    expect(await m.billing.chargeScan("un5")).toBe("free");

    await m.webhook.processStripeEvent(subscriptionEvent("customer.subscription.deleted", "sub_U5", "canceled"));
    expect(await m.billing.hasUnlimitedPlan("un5")).toBe(false);
    expect(await m.billing.chargeScan("un5")).toBe("free");
  });

  it("does not say an account with no plan, or a legacy counted plan, is unlimited", async () => {
    expect(await m.billing.hasUnlimitedPlan("nobody")).toBe(false);
    await m.webhook.processStripeEvent(subscriptionCompleted("un6", "sub_U6", "pro"));
    await m.webhook.processStripeEvent(invoicePaid("sub_U6", "un6", undefined, "pro"));
    expect(await m.billing.hasUnlimitedPlan("un6")).toBe(false);
  });

  it("gives a failed scan back as nothing at all: no counter, and above all no credit", async () => {
    // A counted plan returns the scan it took. An unlimited plan took none, so a refund that
    // minted a credit would hand out a paid-for scan for free, on every failure.
    await subscribe("un7", "sub_U7");
    const scanId = await insertScan("un7", "included");

    await m.billing.refundFailedScan(scanId);

    expect(await balance("un7")).toBe(0);
    expect((await plan("un7"))?.includedScansRemaining).toBe(0);
  });

  it("gives a failed scan back as nothing even after the plan was cancelled", async () => {
    // The counted-plan rule is "return it as a credit if the plan has since been cancelled".
    // That rule must not apply here, where there was never anything to return.
    await subscribe("un8", "sub_U8");
    const scanId = await insertScan("un8", "included");
    await m.webhook.processStripeEvent(subscriptionEvent("customer.subscription.deleted", "sub_U8", "canceled"));

    await m.billing.refundFailedScan(scanId);

    expect(await balance("un8")).toBe(0);
  });

  it("refunds a rejected launch the same way: nothing", async () => {
    await subscribe("un9", "sub_U9");
    const paid = await m.billing.chargeScan("un9");
    expect(paid).toBe("included");

    await m.billing.refundCharge("un9", paid);

    expect(await balance("un9")).toBe(0);
    expect((await plan("un9"))?.includedScansRemaining).toBe(0);
  });

  it("still returns a counted plan's scan as before, so the legacy path is unchanged", async () => {
    await m.webhook.processStripeEvent(subscriptionCompleted("un10", "sub_U10", "pro"));
    await m.webhook.processStripeEvent(invoicePaid("sub_U10", "un10", undefined, "pro"));
    const before = (await plan("un10"))!.includedScansRemaining;
    const paid = await m.billing.chargeScan("un10");
    // Three free scans come first; spend them so the next charge reaches the plan.
    expect(paid).toBe("free");
    const { trialScansUsedBy } = await import("./freeTrial");
    for (let i = 0; i < 3; i++) await insertScan("un10", "free");
    expect(await trialScansUsedBy("un10")).toBeGreaterThanOrEqual(3);
    const included = await m.billing.chargeScan("un10");
    expect(included).toBe("included");
    expect((await plan("un10"))!.includedScansRemaining).toBe(before - 1);

    await m.billing.refundCharge("un10", included);
    expect((await plan("un10"))!.includedScansRemaining).toBe(before);
  });
});

import { describe, it, expect, vi, beforeEach } from "vitest";

const calls: string[] = [];
const state: { sub: { status: string; latest_invoice: string | null }; payments: Array<{ payment: { payment_intent: string | null } }>; throwOn: string | null } = {
  sub: { status: "active", latest_invoice: "in_1" },
  payments: [{ payment: { payment_intent: "pi_1" } }],
  throwOn: null,
};

const step = (name: string, result: unknown) => async () => {
  calls.push(name);
  if (state.throwOn === name) throw new Error(`${name} exploded`);
  return result;
};

vi.mock("./stripe", () => ({
  get stripe() {
    return {
      subscriptions: {
        retrieve: async () => step("retrieve", state.sub)(),
        cancel: async () => step("cancel", {})(),
      },
      invoicePayments: { list: async () => step("payments", { data: state.payments })() },
      refunds: { create: async () => step("refund", {})() },
    };
  },
}));

import { dropDuplicateSubscription } from "./duplicateSubscription";

beforeEach(() => {
  calls.length = 0;
  state.sub = { status: "active", latest_invoice: "in_1" };
  state.payments = [{ payment: { payment_intent: "pi_1" } }];
  state.throwOn = null;
});

describe("dropDuplicateSubscription", () => {
  it("cancels the subscription, then refunds what it charged", async () => {
    await dropDuplicateSubscription("sub_2");
    expect(calls).toEqual(["retrieve", "cancel", "payments", "refund"]);
  });

  it("does not cancel one that is already cancelled, but still refunds", async () => {
    state.sub.status = "canceled";
    await dropDuplicateSubscription("sub_2");
    expect(calls).toEqual(["retrieve", "payments", "refund"]);
  });

  it("refunds nothing when the invoice has no payment behind it", async () => {
    state.payments = [];
    await dropDuplicateSubscription("sub_2");
    expect(calls).not.toContain("refund");
  });

  it("never throws, so a Stripe failure cannot fail the webhook", async () => {
    state.throwOn = "cancel";
    await expect(dropDuplicateSubscription("sub_2")).resolves.toBeUndefined();
    expect(calls).toEqual(["retrieve", "cancel"]);
  });
});

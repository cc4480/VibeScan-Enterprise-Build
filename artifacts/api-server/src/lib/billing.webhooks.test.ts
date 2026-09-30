import { m, evId, packCompleted, suite, billingHarness } from "./billing.testkit";
import { it, expect } from "vitest";

/** Billing against a real Postgres — see billing.testkit.ts for how to run it. */



suite("billing (real Postgres)", () => {
  const { balance, plan, setAllowance, insertScan } = billingHarness();

  // ── Bug 1: duplicate delivery ──────────────────────────────────────────────
  it("credits a pack exactly once, however many times Stripe delivers it", async () => {
    const event = packCompleted("u1", "pack_10", "paid");
    const first = await m.webhook.processStripeEvent(event);
    const again = await m.webhook.processStripeEvent(event);
    const third = await m.webhook.processStripeEvent(event);

    expect(first.duplicate).toBe(false);
    expect(again.duplicate).toBe(true);
    expect(third.duplicate).toBe(true);
    expect(await balance("u1")).toBe(10); // was 30 before the ledger
  });

  it("applies each duplicate once even when the deliveries race each other", async () => {
    const event = packCompleted("u1", "pack_50", "paid");
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => m.webhook.processStripeEvent(event)));
    const applied = results.filter((r) => r.status === "fulfilled" && !r.value.duplicate).length;
    expect(applied).toBe(1);
    expect(await balance("u1")).toBe(50);
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

    const retry = await m.webhook.processStripeEvent(packCompleted("u1", "pack_10", "paid", id));
    expect(retry.duplicate).toBe(false);
    expect(await balance("u1")).toBe(10);
  });

  // ── Bug 2: lost updates ────────────────────────────────────────────────────
  it("loses no credits when purchases and spends land at the same time", async () => {
    await m.billing.addCredits(m.db.db, "u2", 10);
    const { spendOneCredit } = await import("./credits");

    await Promise.all([
      ...Array.from({ length: 6 }, () => m.webhook.processStripeEvent(packCompleted("u2", "pack_10", "paid"))),
      ...Array.from({ length: 4 }, () => spendOneCredit("u2")),
    ]);
    // 10 + six 10-packs (60) - 4 spent. Read-then-write lost some of these.
    expect(await balance("u2")).toBe(66);
  });

  // ── Bug 3: money not yet taken ─────────────────────────────────────────────
  it("grants nothing for an unpaid checkout, then grants when the payment clears", async () => {
    const r = await m.webhook.processStripeEvent(packCompleted("u3", "pack_10", "unpaid"));
    expect(r.applied).toMatch(/deferred/);
    expect(await balance("u3")).toBe(0);

    const cleared = { ...(packCompleted("u3", "pack_10", "paid") as object), type: "checkout.session.async_payment_succeeded" };
    await m.webhook.processStripeEvent(cleared as never);
    expect(await balance("u3")).toBe(10);
  });

  it("ignores a pack that is not sold (a retired per-scan tier grants nothing)", async () => {
    await m.webhook.processStripeEvent(packCompleted("u3", "deep", "paid"));
    expect(await balance("u3")).toBe(0);
  });
});

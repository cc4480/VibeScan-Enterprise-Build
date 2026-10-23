import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { PRICE_MAP, CREDITS_MAP, PACKS_ON_SALE } from "./stripe";

/**
 * PRICE_MAP and CREDITS_MAP are two separate objects that have to agree, and
 * nothing before this checked that they did. That gap already produced one
 * real defect this session: a pack description claiming a savings figure
 * ("save $85 vs 5 singles") for a single-scan price that was never actually
 * sold, so the number was fiction from the day it was written. These pin the
 * two maps to each other and to arithmetic, not to today's specific numbers,
 * so a future price change can't reintroduce the same class of lie.
 */

// The retired per-scan tiers price without crediting, on purpose — see the
// money-leak test in routes/checkout.test.ts. They are excluded here rather
// than asserted against, because this file is about what IS still sold.
// Retired tiers price without crediting, on purpose — see the money-leak test in
// routes/checkout.test.ts. "single", "pack_5" and "pack_20" were retired on
// 2026-09-24, never having been sold.
const RETIRED = new Set(["basic", "deep", "single", "pack_5", "pack_20"]);
const sold = Object.keys(PRICE_MAP).filter((t) => !RETIRED.has(t));

describe("every sellable tier is priced and creditable", () => {
  it("has a CREDITS_MAP entry for everything priced outside the retired tiers", () => {
    for (const tier of sold) {
      expect(CREDITS_MAP[tier], `${tier} prices but grants no credits`).toBeGreaterThan(0);
    }
  });

  it("has a price for everything CREDITS_MAP will grant", () => {
    for (const tier of Object.keys(CREDITS_MAP)) {
      expect(PRICE_MAP[tier], `${tier} grants credits but has no price`).toBeDefined();
    }
  });

  it("prices every sellable tier in whole cents, as Stripe requires", () => {
    for (const tier of sold) {
      const amount = PRICE_MAP[tier]!.amount;
      expect(Number.isInteger(amount), tier).toBe(true);
      expect(amount, tier).toBeGreaterThan(0);
    }
  });
});

describe("pack pricing", () => {
  const perCredit = (tier: string) => PRICE_MAP[tier]!.amount / CREDITS_MAP[tier]!;
  const packs = [...sold].sort((a, b) => CREDITS_MAP[a]! - CREDITS_MAP[b]!);

  it("still credits the packs decided on 2026-09-24: 10 for $12, 50 for $49", () => {
    // The grant table, not the shop window: a payment that arrives for one of these is credited
    // even though none is on sale any more (see PACKS_ON_SALE).
    expect(packs).toEqual(["pack_10", "pack_50"]);
    expect([PRICE_MAP["pack_10"]!.amount, CREDITS_MAP["pack_10"]]).toEqual([1200, 10]);
    expect([PRICE_MAP["pack_50"]!.amount, CREDITS_MAP["pack_50"]]).toEqual([4900, 50]);
  });

  it("gives the larger pack a better per-credit rate, not just a bigger number", () => {
    // The old $10-for-5 / $40-for-20 pricing was $2 a credit both ways: a discount in name only.
    for (let i = 1; i < packs.length; i++) {
      expect(perCredit(packs[i]!), `${packs[i]} should cost less per credit than ${packs[i - 1]}`)
        .toBeLessThan(perCredit(packs[i - 1]!));
    }
  });
});

describe("PACKS_ON_SALE", () => {
  it("is empty: no credit pack is sold since the move to one unlimited plan (2026-10-03)", () => {
    expect(PACKS_ON_SALE).toEqual([]);
  });

  it("only ever lists a pack that grants credits, so a sale cannot take money and grant nothing", () => {
    for (const tier of PACKS_ON_SALE) expect(CREDITS_MAP[tier], tier).toBeGreaterThan(0);
  });
});

describe("warnIfPaymentsMisconfigured", () => {
  // The one payment state worth shouting about at boot: checkout can take money
  // (key set) while the webhook refuses every event (no secret), so nobody who
  // pays is ever credited — and nothing else would surface it but a customer.
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  it("errors when payments can be taken but never credited", async () => {
    const { warnIfPaymentsMisconfigured } = await import("./stripe");
    process.env["STRIPE_SECRET_KEY"] = "sk_test_x";
    delete process.env["STRIPE_WEBHOOK_SECRET"];
    delete process.env["DISABLE_PAYMENTS"];
    const log = { warn: vi.fn(), error: vi.fn() };
    warnIfPaymentsMisconfigured(log);
    expect(log.error).toHaveBeenCalledTimes(1);
    expect(log.error.mock.calls[0]![1]).toMatch(/customers can pay/);
  });

  it("stays quiet when both halves are configured, or neither is", async () => {
    const { warnIfPaymentsMisconfigured } = await import("./stripe");
    delete process.env["DISABLE_PAYMENTS"];
    for (const [key, secret] of [["sk_test_x", "whsec_x"], [undefined, undefined]] as const) {
      if (key) process.env["STRIPE_SECRET_KEY"] = key; else delete process.env["STRIPE_SECRET_KEY"];
      if (secret) process.env["STRIPE_WEBHOOK_SECRET"] = secret; else delete process.env["STRIPE_WEBHOOK_SECRET"];
      const log = { warn: vi.fn(), error: vi.fn() };
      warnIfPaymentsMisconfigured(log);
      expect(log.error).not.toHaveBeenCalled();
      expect(log.warn).not.toHaveBeenCalled();
    }
  });

  it("calls the logger as a method, so pino keeps its `this`", async () => {
    const { warnIfPaymentsMisconfigured } = await import("./stripe");
    process.env["STRIPE_SECRET_KEY"] = "sk_test_x";
    delete process.env["STRIPE_WEBHOOK_SECRET"];
    const seen: unknown[] = [];
    const log = {
      tag: "logger",
      warn() {},
      error(this: { tag: string }) {
        seen.push(this?.tag);
      },
    };
    warnIfPaymentsMisconfigured(log);
    expect(seen).toEqual(["logger"]);
  });
});

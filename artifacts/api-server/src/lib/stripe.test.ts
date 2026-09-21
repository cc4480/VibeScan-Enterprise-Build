import { describe, it, expect } from "vitest";
import { PRICE_MAP, CREDITS_MAP } from "./stripe";

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
const RETIRED = new Set(["basic", "deep"]);
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

describe("a pack is never priced worse than buying that many singles", () => {
  const singleAmount = PRICE_MAP["single"]?.amount;

  it("has a single-credit tier to measure a pack discount against", () => {
    // Without this, "X% off buying singles" in a pack's own description is
    // the same unbacked claim that was already found and removed once.
    expect(singleAmount, "no 'single' tier — pack discount claims have nothing to be measured against").toBeDefined();
  });

  it("charges every pack at or below the single-credit rate", () => {
    for (const tier of sold) {
      if (tier === "single") continue;
      const credits = CREDITS_MAP[tier]!;
      const packAmount = PRICE_MAP[tier]!.amount;
      const equivalentSingles = credits * singleAmount!;
      expect(packAmount, `${tier}: ${packAmount}c for ${credits} credits vs ${equivalentSingles}c buying them one at a time`)
        .toBeLessThanOrEqual(equivalentSingles);
    }
  });

  it("gives the largest pack the best or an equal per-credit rate", () => {
    // Not just cheaper than buying singles — cheaper per unit than the smaller
    // pack, which is the actual shape a volume discount is supposed to have.
    // This is the property the old $10-for-5 / $40-for-20 pricing violated:
    // both worked out to exactly $2/credit, a discount in name only.
    const perCredit = (tier: string) => PRICE_MAP[tier]!.amount / CREDITS_MAP[tier]!;
    const packs = sold.filter((t) => t !== "single" && CREDITS_MAP[t]! > 1);
    const sorted = [...packs].sort((a, b) => CREDITS_MAP[a]! - CREDITS_MAP[b]!);

    for (let i = 1; i < sorted.length; i++) {
      expect(perCredit(sorted[i]!), `${sorted[i]} should not cost more per credit than ${sorted[i - 1]}`)
        .toBeLessThanOrEqual(perCredit(sorted[i - 1]!));
    }
  });
});

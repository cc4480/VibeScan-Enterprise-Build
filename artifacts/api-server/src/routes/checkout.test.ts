import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * This is the route that was missing entirely: nothing created a Checkout
 * Session, so the webhook that credits an account could never be reached. The
 * two failure directions that matter here are not symmetric — charging someone
 * and crediting the wrong tier is a support ticket and a chargeback risk;
 * refusing to charge someone is a missed sale. Get the first one wrong and it
 * costs real money.
 */

const state: {
  createArgs: unknown;
  createResolves: { id: string; url: string | null } | null;
  createThrows: Error | null;
  stripeConfigured: boolean;
} = { createArgs: null, createResolves: null, createThrows: null, stripeConfigured: true };

vi.mock("../lib/stripe", () => ({
  get stripe() {
    if (!state.stripeConfigured) return null;
    return {
      checkout: {
        sessions: {
          create: (args: unknown) => {
            state.createArgs = args;
            if (state.createThrows) return Promise.reject(state.createThrows);
            return Promise.resolve(state.createResolves);
          },
        },
      },
    };
  },
  PRICE_MAP: {
    // Mirrors the real map's shape, including a legacy per-scan entry that
    // must never be buyable now that tiers are retired.
    basic: { amount: 900, name: "SecScan Basic", description: "legacy" },
    deep: { amount: 1900, name: "SecScan Deep", description: "legacy" },
    pack_5: { amount: 1000, name: "SecScan 5-Scan Pack", description: "5 credits" },
    pack_20: { amount: 4000, name: "SecScan 20-Scan Pack", description: "20 credits" },
    // Withdrawn from sale but still credited: priced, in CREDITS_MAP, not in PACKS_ON_SALE.
    pack_old: { amount: 2000, name: "SecScan Old Pack", description: "10 credits" },
  },
  CREDITS_MAP: { pack_5: 5, pack_20: 20, pack_old: 10 },
  PACKS_ON_SALE: ["pack_5", "pack_20"],
  getOrigin: () => "https://secscan.us",
}));

function makeRes() {
  const res: Record<string, unknown> & { statusCode: number; body: unknown } = {
    statusCode: 200,
    body: null,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

function makeReq(body: unknown = {}, overrides: Record<string, unknown> = {}) {
  return {
    body,
    headers: {},
    isAuthenticated: () => true,
    user: { id: "user-1", email: "someone@example.com" },
    log: { error: vi.fn(), info: vi.fn() },
    ...overrides,
  };
}

interface RouteLayer {
  route?: { path: string; methods: Record<string, boolean>; stack: { handle: Handler }[] };
}
type Handler = (req: unknown, res: unknown) => Promise<void> | void;

async function handlerFor(method: "get" | "post", path: string): Promise<Handler> {
  const mod = await import("./checkout.js");
  const router = mod.default as unknown as { stack: RouteLayer[] };
  const layer = router.stack.find((l) => l.route?.path === path && l.route.methods[method]);
  if (!layer?.route) throw new Error(`no ${method} ${path} route`);
  return layer.route.stack[0]!.handle;
}

beforeEach(() => {
  state.createArgs = null;
  state.createResolves = { id: "cs_test_1", url: "https://checkout.stripe.com/session/cs_test_1" };
  state.createThrows = null;
  state.stripeConfigured = true;
  vi.resetModules();
});

describe("GET /checkout/packs", () => {
  it("lists only tiers that grant credits, not the retired per-scan ones", async () => {
    const h = await handlerFor("get", "/checkout/packs");
    const res = makeRes();
    await h(makeReq(), res);

    const body = res.body as { packs: Array<{ tier: string }> };
    const tiers = body.packs.map((p) => p.tier);
    expect(tiers).toEqual(["pack_5", "pack_20"]);
    // Withdrawn from sale: it grants credits, but the page must not offer it.
    expect(tiers).not.toContain("pack_old");
    expect(tiers).not.toContain("basic");
    expect(tiers).not.toContain("deep");
  });

  it("prices what it advertises from the same map checkout will charge from", async () => {
    const h = await handlerFor("get", "/checkout/packs");
    const res = makeRes();
    await h(makeReq(), res);

    const body = res.body as { packs: Array<{ tier: string; amountCents: number; credits: number }> };
    const pack5 = body.packs.find((p) => p.tier === "pack_5")!;
    expect(pack5.amountCents).toBe(1000);
    expect(pack5.credits).toBe(5);
  });

  it("reports enabled: false when no Stripe key is configured", async () => {
    state.stripeConfigured = false;
    const h = await handlerFor("get", "/checkout/packs");
    const res = makeRes();
    await h(makeReq(), res);

    expect((res.body as { enabled: boolean }).enabled).toBe(false);
  });

  it("states the per-account scan caps, so the page can show them beside \"unlimited\"", async () => {
    const h = await handlerFor("get", "/checkout/packs");
    const res = makeRes();
    await h(makeReq(), res);

    expect((res.body as { scanLimits: unknown }).scanLimits).toEqual({ perHour: 5, perDay: 20 });
  });

  it("does not require authentication — the price list is not sensitive", async () => {
    const h = await handlerFor("get", "/checkout/packs");
    const res = makeRes();
    await h(makeReq({}, { isAuthenticated: () => false, user: undefined }), res);

    expect(res.statusCode).toBe(200);
  });
});

describe("POST /checkout/credits — who may buy", () => {
  it("refuses an unauthenticated caller", async () => {
    const h = await handlerFor("post", "/checkout/credits");
    const res = makeRes();
    await h(makeReq({ tier: "pack_5" }, { isAuthenticated: () => false, user: undefined }), res);

    expect(res.statusCode).toBe(401);
    expect(state.createArgs).toBeNull();
  });

  it("answers 503 rather than failing obscurely when Stripe is not configured", async () => {
    state.stripeConfigured = false;
    const h = await handlerFor("post", "/checkout/credits");
    const res = makeRes();
    await h(makeReq({ tier: "pack_5" }), res);

    expect(res.statusCode).toBe(503);
    expect(state.createArgs).toBeNull();
  });
});

describe("POST /checkout/credits — what it will and won't sell", () => {
  it("refuses a tier that is not in CREDITS_MAP, even though it prices in PRICE_MAP", async () => {
    // The regression this whole route exists to prevent: "basic" and "deep"
    // still have a price because PRICE_MAP carries retired tiers, but they
    // grant no credits. Selling one would take money and credit nothing —
    // the webhook looks the tier up in CREDITS_MAP, not PRICE_MAP.
    const h = await handlerFor("post", "/checkout/credits");
    const res = makeRes();
    await h(makeReq({ tier: "basic" }), res);

    expect(res.statusCode).toBe(400);
    expect(state.createArgs).toBeNull();
  });

  it("refuses a pack that was withdrawn from sale, though it still grants credits when an old payment arrives", async () => {
    // The grant table (CREDITS_MAP) keeps the pack so a checkout opened before the change is
    // still credited when it is paid. That is a reason to keep crediting it, not to sell it.
    const h = await handlerFor("post", "/checkout/credits");
    const res = makeRes();
    await h(makeReq({ tier: "pack_old" }), res);

    expect(res.statusCode).toBe(400);
    expect(state.createArgs).toBeNull();
  });

  it("refuses an unknown tier", async () => {
    const h = await handlerFor("post", "/checkout/credits");
    const res = makeRes();
    await h(makeReq({ tier: "enterprise" }), res);

    expect(res.statusCode).toBe(400);
  });

  it("refuses a missing or non-string tier without throwing", async () => {
    const h = await handlerFor("post", "/checkout/credits");
    for (const body of [{}, { tier: 5 }, { tier: null }]) {
      const res = makeRes();
      await h(makeReq(body), res);
      expect(res.statusCode, JSON.stringify(body)).toBe(400);
    }
  });
});

describe("POST /checkout/credits — the session Stripe is asked to create", () => {
  it("charges exactly the price in PRICE_MAP for the requested tier", async () => {
    const h = await handlerFor("post", "/checkout/credits");
    await h(makeReq({ tier: "pack_5" }), makeRes());

    const args = state.createArgs as { line_items: Array<{ price_data: { unit_amount: number } }> };
    expect(args.line_items[0]!.price_data.unit_amount).toBe(1000);
  });

  it("stamps metadata the webhook depends on: type, user_id, tier", async () => {
    const h = await handlerFor("post", "/checkout/credits");
    await h(makeReq({ tier: "pack_20" }, { user: { id: "user-42", email: "a@b.com" } }), makeRes());

    const args = state.createArgs as { metadata: Record<string, string> };
    expect(args.metadata).toEqual({ type: "credits", user_id: "user-42", tier: "pack_20" });
  });

  it("mirrors the same metadata onto the PaymentIntent", async () => {
    // payment_intent.payment_failed carries metadata from the intent, not the
    // session. Metadata only on the session would make a failed payment
    // unattributable.
    const h = await handlerFor("post", "/checkout/credits");
    await h(makeReq({ tier: "pack_5" }, { user: { id: "user-9", email: "a@b.com" } }), makeRes());

    const args = state.createArgs as { payment_intent_data: { metadata: Record<string, string> } };
    expect(args.payment_intent_data.metadata).toEqual({ type: "credits", user_id: "user-9", tier: "pack_5" });
  });

  it("is a one-time payment, not a subscription", async () => {
    const h = await handlerFor("post", "/checkout/credits");
    await h(makeReq({ tier: "pack_5" }), makeRes());

    expect((state.createArgs as { mode: string }).mode).toBe("payment");
  });

  it("returns the checkout URL on success", async () => {
    const h = await handlerFor("post", "/checkout/credits");
    const res = makeRes();
    await h(makeReq({ tier: "pack_5" }), res);

    expect(res.statusCode).toBe(201);
    expect(res.body).toEqual({ checkoutUrl: "https://checkout.stripe.com/session/cs_test_1" });
  });
});

describe("POST /checkout/credits — failure does not leak or crash", () => {
  it("answers 502 without the caller's own message when Stripe returns no URL", async () => {
    state.createResolves = { id: "cs_test_2", url: null };
    const h = await handlerFor("post", "/checkout/credits");
    const res = makeRes();
    await h(makeReq({ tier: "pack_5" }), res);

    expect(res.statusCode).toBe(502);
  });

  it("answers 502 and never surfaces Stripe's own error text", async () => {
    // Stripe's error message can name internal configuration — an invalid API
    // key error literally quotes the key. It must never reach the response.
    state.createThrows = new Error("No such price: 'price_super_secret_internal_id'");
    const h = await handlerFor("post", "/checkout/credits");
    const res = makeRes();
    await h(makeReq({ tier: "pack_5" }), res);

    expect(res.statusCode).toBe(502);
    expect(JSON.stringify(res.body)).not.toContain("price_super_secret_internal_id");
  });

  it("logs the failure so a lost sale leaves a trace", async () => {
    state.createThrows = new Error("network error");
    const h = await handlerFor("post", "/checkout/credits");
    const req = makeReq({ tier: "pack_5" });
    await h(req, makeRes());

    expect(req.log.error).toHaveBeenCalled();
  });
});

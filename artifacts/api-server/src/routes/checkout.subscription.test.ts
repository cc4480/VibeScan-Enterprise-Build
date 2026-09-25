import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The subscription half of checkout: start a Starter or Pro plan, manage it, and
 * report what a user can do next. The webhook that applies these sessions is
 * tested against a real database in lib/billing.integration.test.ts; this pins
 * what the session is CREATED with, because a session missing its metadata is
 * a customer charged every month for a plan the webhook cannot attach to them.
 */

const state: {
  sessionArgs: Record<string, unknown> | null;
  portalArgs: Record<string, unknown> | null;
  planRow: Record<string, unknown> | null;
  stripeConfigured: boolean;
} = { sessionArgs: null, portalArgs: null, planRow: null, stripeConfigured: true };

vi.mock("../lib/stripe", () => ({
  get stripe() {
    if (!state.stripeConfigured) return null;
    return {
      checkout: {
        sessions: {
          create: (args: Record<string, unknown>) => {
            state.sessionArgs = args;
            return Promise.resolve({ id: "cs_test", url: "https://checkout.stripe.com/c/cs_test" });
          },
        },
      },
      billingPortal: {
        sessions: {
          create: (args: Record<string, unknown>) => {
            state.portalArgs = args;
            return Promise.resolve({ url: "https://billing.stripe.com/p/session" });
          },
        },
      },
    };
  },
  PRICE_MAP: { single: { amount: 1200, name: "Single", description: "" } },
  CREDITS_MAP: { single: 1 },
  getOrigin: () => "https://secscan.us",
}));

vi.mock("@workspace/db", () => {
  const chain = {
    select: () => chain,
    from: () => chain,
    where: () => chain,
    limit: () => Promise.resolve(state.planRow ? [state.planRow] : []),
  };
  return { db: chain, billingSubscriptionsTable: { userId: "user_id" } };
});
vi.mock("../lib/credits", () => ({ creditBalance: () => Promise.resolve(3) }));
vi.mock("../lib/freeTrial", () => ({
  trialScansUsedBy: () => Promise.resolve(1),
  FREE_TRIAL_SCAN_LIMIT: 2,
  freeScansResetAt: () => new Date("2026-10-01T00:00:00Z"),
}));

function makeRes() {
  const res: Record<string, unknown> & { statusCode: number; body: any } = {
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

function makeReq(overrides: Record<string, unknown> = {}) {
  return {
    body: {},
    headers: {},
    isAuthenticated: () => true,
    user: { id: "user-1", email: "someone@example.com" },
    log: { error: vi.fn(), info: vi.fn() },
    ...overrides,
  };
}

type Handler = (req: unknown, res: unknown) => Promise<void> | void;
async function handlerFor(method: "get" | "post", path: string): Promise<Handler> {
  const mod = await import("./checkout.js");
  const router = mod.default as unknown as {
    stack: { route?: { path: string; methods: Record<string, boolean>; stack: { handle: Handler }[] } }[];
  };
  const layer = router.stack.find((l) => l.route?.path === path && l.route.methods[method]);
  if (!layer?.route) throw new Error(`no ${method} ${path}`);
  return layer.route.stack[0]!.handle;
}

beforeEach(() => {
  state.sessionArgs = null;
  state.portalArgs = null;
  state.planRow = null;
  state.stripeConfigured = true;
});

describe("POST /checkout/subscription", () => {
  it("creates a $49 Pro session when no plan is named, carrying the user on BOTH session and subscription", async () => {
    // No body: the one-plan client this endpoint served before there were two.
    const res = makeRes();
    await (await handlerFor("post", "/checkout/subscription"))(makeReq(), res);

    expect(res.statusCode).toBe(201);
    expect(res.body.checkoutUrl).toMatch(/^https:\/\/checkout\.stripe\.com/);

    const args = state.sessionArgs as any;
    expect(args.mode).toBe("subscription");
    const price = args.line_items[0].price_data;
    expect(price.unit_amount).toBe(4900);
    expect(price.recurring).toEqual({ interval: "month" });
    // The session's metadata reaches checkout.session.completed; the
    // subscription's is snapshotted onto every invoice — invoice.paid needs it
    // to find the customer when it arrives first.
    expect(args.metadata).toMatchObject({ type: "subscription", user_id: "user-1", plan: "pro" });
    expect(args.subscription_data.metadata).toMatchObject({ type: "subscription", user_id: "user-1", plan: "pro" });
  });

  it("sells Starter at $19 when asked, and records the plan for the webhook", async () => {
    const res = makeRes();
    await (await handlerFor("post", "/checkout/subscription"))(makeReq({ body: { plan: "starter" } }), res);
    expect(res.statusCode).toBe(201);
    const args = state.sessionArgs as any;
    expect(args.line_items[0].price_data.unit_amount).toBe(1900);
    expect(args.subscription_data.metadata.plan).toBe("starter");
  });

  it("refuses a plan that is not sold, without starting a session", async () => {
    for (const plan of ["enterprise", "constructor", 5]) {
      const res = makeRes();
      await (await handlerFor("post", "/checkout/subscription"))(makeReq({ body: { plan } }), res);
      expect(res.statusCode, String(plan)).toBe(400);
      expect(res.body.code).toBe("unknown_plan");
    }
    expect(state.sessionArgs).toBeNull();
  });

  it("refuses a second live subscription instead of charging twice", async () => {
    state.planRow = { status: "active", stripeCustomerId: "cus_1" };
    const res = makeRes();
    await (await handlerFor("post", "/checkout/subscription"))(makeReq(), res);
    expect(res.statusCode).toBe(409);
    expect(res.body.code).toBe("already_subscribed");
    expect(state.sessionArgs).toBeNull();
  });

  it("lets a cancelled subscriber come back, on their existing Stripe customer", async () => {
    state.planRow = { status: "cancelled", stripeCustomerId: "cus_old" };
    const res = makeRes();
    await (await handlerFor("post", "/checkout/subscription"))(makeReq(), res);
    expect(res.statusCode).toBe(201);
    expect((state.sessionArgs as any).customer).toBe("cus_old");
  });

  it("requires sign-in, and says plainly when payments are not configured", async () => {
    const unauth = makeRes();
    await (await handlerFor("post", "/checkout/subscription"))(makeReq({ isAuthenticated: () => false }), unauth);
    expect(unauth.statusCode).toBe(401);

    state.stripeConfigured = false;
    const off = makeRes();
    await (await handlerFor("post", "/checkout/subscription"))(makeReq(), off);
    expect(off.statusCode).toBe(503);
  });
});

describe("POST /billing/portal", () => {
  it("opens Stripe's portal for the subscriber's own customer", async () => {
    state.planRow = { status: "active", stripeCustomerId: "cus_mine" };
    const res = makeRes();
    await (await handlerFor("post", "/billing/portal"))(makeReq(), res);
    expect(res.statusCode).toBe(201);
    expect((state.portalArgs as any).customer).toBe("cus_mine");
  });

  it("has nothing to open for someone who never subscribed", async () => {
    const res = makeRes();
    await (await handlerFor("post", "/billing/portal"))(makeReq(), res);
    expect(res.statusCode).toBe(404);
    expect(state.portalArgs).toBeNull();
  });
});

describe("GET /billing/status", () => {
  it("reports free scans, credits and the plan in one answer", async () => {
    state.planRow = {
      plan: "pro",
      status: "active",
      includedScansRemaining: 4,
      urlLimit: 3,
      currentPeriodEnd: new Date("2026-10-22T00:00:00Z"),
      stripeCustomerId: "cus_1",
    };
    const res = makeRes();
    await (await handlerFor("get", "/billing/status"))(makeReq(), res);
    expect(res.body).toMatchObject({
      freeScansRemaining: 1,
      credits: 3,
      subscription: { plan: "pro", status: "active", includedScansRemaining: 4, urlLimit: 3, canManage: true },
      paymentsEnabled: true,
    });
  });
});

describe("anonymous (browser-only) identities", () => {
  // First-time visitors get an account with no email. A purchase on one would
  // live only in that browser's storage — unrecoverable, and a subscription
  // nobody could sign in to cancel.
  const anon = () => makeReq({ user: { id: "anon-1", email: null } });

  it("cannot start a subscription", async () => {
    const res = makeRes();
    await (await handlerFor("post", "/checkout/subscription"))(anon(), res);
    expect(res.statusCode).toBe(403);
    expect(res.body.code).toBe("account_required");
    expect(state.sessionArgs).toBeNull();
  });

  it("cannot buy a credit pack", async () => {
    const res = makeRes();
    await (await handlerFor("post", "/checkout/credits"))({ ...anon(), body: { tier: "single" } }, res);
    expect(res.statusCode).toBe(403);
    expect(res.body.code).toBe("account_required");
    expect(state.sessionArgs).toBeNull();
  });
});

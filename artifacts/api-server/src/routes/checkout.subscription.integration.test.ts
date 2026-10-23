/**
 * The subscription half of checkout: start a plan, manage it, and report what a user can do next. The webhook that
 * applies these sessions is tested against a real database in lib/billing.integration.test.ts; this pins what the
 * session is CREATED with, because a session missing its metadata is a customer charged every month for a plan the
 * webhook cannot attach to them.
 *
 * Over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): real plan rows, real credits, real free-scan
 * counts. The one stand-in is the Stripe client (lib/stripe), which records what it is asked to create and answers
 * with a Checkout URL, because a test must never open a real payment session.
 */
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { dbSuiteOf, useRealDb, openDb, startApp, uniqueEmail, type TestApp } from "../lib/realDb.testkit";

useRealDb();
delete process.env["FREE_TRIAL_SCAN_LIMIT"]; // the default of three free scans

const stripeState = vi.hoisted(() => ({
  sessionArgs: null as Record<string, unknown> | null,
  portalArgs: null as Record<string, unknown> | null,
  stripeConfigured: true,
}));

vi.mock("../lib/stripe", () => ({
  get stripe() {
    if (!stripeState.stripeConfigured) return null;
    return {
      checkout: {
        sessions: {
          create: (args: Record<string, unknown>) => {
            stripeState.sessionArgs = args;
            return Promise.resolve({ id: "cs_test", url: "https://checkout.stripe.com/c/cs_test" });
          },
        },
      },
      billingPortal: {
        sessions: {
          create: (args: Record<string, unknown>) => {
            stripeState.portalArgs = args;
            return Promise.resolve({ url: "https://billing.stripe.com/p/session" });
          },
        },
      },
    };
  },
  PRICE_MAP: { single: { amount: 1200, name: "Single", description: "" } },
  CREDITS_MAP: { single: 1 },
  PACKS_ON_SALE: [],
  getOrigin: () => "https://secscan.us",
}));

dbSuiteOf(describe)("checkout subscriptions (real Postgres, stand-in Stripe)", () => {
  let dbMod: typeof import("@workspace/db");
  let app: TestApp;
  const owners: string[] = [];
  let n = 0;
  const person = () => {
    const id = `co-${Date.now()}-${++n}`;
    owners.push(id);
    return { id, email: uniqueEmail("checkout") };
  };
  const post = (path: string, body?: unknown) =>
    fetch(app.base + path, { method: "POST", headers: { "content-type": "application/json" }, body: body === undefined ? "{}" : JSON.stringify(body) });
  const plan = (userId: string, fields: Partial<typeof dbMod.billingSubscriptionsTable.$inferInsert>) =>
    dbMod.db.insert(dbMod.billingSubscriptionsTable).values({ userId, plan: "unlimited", status: "active", urlLimit: 5, ...fields });

  beforeAll(async () => {
    dbMod = await openDb();
    const { default: router } = await import("./checkout");
    app = startApp(router);
  }, 60_000);

  beforeEach(() => {
    stripeState.sessionArgs = null;
    stripeState.portalArgs = null;
    stripeState.stripeConfigured = true;
  });

  afterAll(async () => {
    app?.server.close();
    const { inArray } = await import("drizzle-orm");
    if (owners.length) {
      await dbMod.db.delete(dbMod.billingSubscriptionsTable).where(inArray(dbMod.billingSubscriptionsTable.userId, owners));
      await dbMod.db.delete(dbMod.creditsTable).where(inArray(dbMod.creditsTable.userId, owners));
      await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, owners));
    }
    await dbMod?.pool?.end?.();
  });

  describe("POST /checkout/subscription", () => {
    it("creates a $19 Unlimited session when no plan is named, carrying the user on BOTH session and subscription", async () => {
      // No body: a client written before plans had keys gets the one plan on sale.
      const p = person();
      app.as(p);
      const res = await post("/checkout/subscription");
      expect(res.status).toBe(201);
      expect(((await res.json()) as any).checkoutUrl).toMatch(/^https:\/\/checkout\.stripe\.com/);

      const args = stripeState.sessionArgs as any;
      expect(args.mode).toBe("subscription");
      const price = args.line_items[0].price_data;
      expect(price.unit_amount).toBe(1900);
      expect(price.recurring).toEqual({ interval: "month" });
      expect(price.product_data.name).toBe("SecScan Unlimited");
      // The session's metadata reaches checkout.session.completed; the subscription's is snapshotted onto every
      // invoice: invoice.paid needs it to find the customer when it arrives first.
      expect(args.metadata).toMatchObject({ type: "subscription", user_id: p.id, plan: "unlimited" });
      expect(args.subscription_data.metadata).toMatchObject({ type: "subscription", user_id: p.id, plan: "unlimited" });
    });

    it("sells the unlimited plan by name too, and records it for the webhook", async () => {
      app.as(person());
      const res = await post("/checkout/subscription", { plan: "unlimited" });
      expect(res.status).toBe(201);
      const args = stripeState.sessionArgs as any;
      expect(args.line_items[0].price_data.unit_amount).toBe(1900);
      expect(args.subscription_data.metadata.plan).toBe("unlimited");
    });

    it("will not sell Starter or Pro, which are known plans but no longer on sale", async () => {
      // A row carrying one of these keys still resolves to its allowance. Naming one at checkout must not start a
      // session: it would sell a plan that was withdrawn from the page.
      app.as(person());
      for (const plan of ["starter", "pro"]) {
        const res = await post("/checkout/subscription", { plan });
        expect(res.status, plan).toBe(400);
        expect(((await res.json()) as any).code, plan).toBe("unknown_plan");
      }
      expect(stripeState.sessionArgs).toBeNull();
    });

    it("refuses a plan that is not sold, without starting a session", async () => {
      app.as(person());
      for (const plan of ["enterprise", "constructor", 5]) {
        const res = await post("/checkout/subscription", { plan });
        expect(res.status, String(plan)).toBe(400);
        expect(((await res.json()) as any).code).toBe("unknown_plan");
      }
      expect(stripeState.sessionArgs).toBeNull();
    });

    it("refuses a second live subscription instead of charging twice", async () => {
      const p = person();
      await plan(p.id, { status: "active", stripeCustomerId: "cus_1" });
      app.as(p);
      const res = await post("/checkout/subscription");
      expect(res.status).toBe(409);
      expect(((await res.json()) as any).code).toBe("already_subscribed");
      expect(stripeState.sessionArgs).toBeNull();
    });

    it("lets a cancelled subscriber come back, on their existing Stripe customer", async () => {
      const p = person();
      await plan(p.id, { status: "cancelled", stripeCustomerId: "cus_old" });
      app.as(p);
      const res = await post("/checkout/subscription");
      expect(res.status).toBe(201);
      expect((stripeState.sessionArgs as any).customer).toBe("cus_old");
    });

    it("requires sign-in, and says plainly when payments are not configured", async () => {
      app.as(null);
      expect((await post("/checkout/subscription")).status).toBe(401);
      stripeState.stripeConfigured = false;
      app.as(person());
      expect((await post("/checkout/subscription")).status).toBe(503);
    });
  });

  describe("POST /billing/portal", () => {
    it("opens Stripe's portal for the subscriber's own customer", async () => {
      const p = person();
      await plan(p.id, { status: "active", stripeCustomerId: "cus_mine" });
      app.as(p);
      const res = await post("/billing/portal");
      expect(res.status).toBe(201);
      expect((stripeState.portalArgs as any).customer).toBe("cus_mine");
    });

    it("has nothing to open for someone who never subscribed", async () => {
      app.as(person());
      expect((await post("/billing/portal")).status).toBe(404);
      expect(stripeState.portalArgs).toBeNull();
    });
  });

  describe("GET /billing/status", () => {
    it("reports free scans, credits and the plan in one answer", async () => {
      const p = person();
      await plan(p.id, { plan: "pro", status: "active", includedScansRemaining: 4, urlLimit: 3, currentPeriodEnd: new Date("2026-10-22T00:00:00Z"), stripeCustomerId: "cus_1" });
      await dbMod.db.insert(dbMod.creditsTable).values({ userId: p.id, balance: 3 });
      await dbMod.db.insert(dbMod.scansTable).values({ userId: p.id, userEmail: p.email, targetUrl: "https://status.example/", tier: "deep", status: "complete" });
      app.as(p);
      const body = await (await fetch(`${app.base}/billing/status`)).json();
      expect(body).toMatchObject({
        freeScansRemaining: 2, // three free, one used this month
        credits: 3,
        subscription: { plan: "pro", status: "active", includedScansRemaining: 4, urlLimit: 3, canManage: true },
        paymentsEnabled: true,
      });
    });

    it("reports a fresh account as three free scans, no credits and no plan", async () => {
      app.as(person());
      const body = (await (await fetch(`${app.base}/billing/status`)).json()) as any;
      expect(body).toMatchObject({ freeScansRemaining: 3, credits: 0, paymentsEnabled: true });
      expect(body.subscription ?? null).toBeNull();
    });
  });

  // First-time visitors get an account with no email. A purchase on one would live only in that browser's storage:
  // unrecoverable, and a subscription nobody could sign in to cancel.
  describe("anonymous (browser-only) identities", () => {
    it("cannot start a subscription", async () => {
      app.as({ id: person().id, email: null });
      const res = await post("/checkout/subscription");
      expect(res.status).toBe(403);
      expect(((await res.json()) as any).code).toBe("account_required");
      expect(stripeState.sessionArgs).toBeNull();
    });

    it("cannot buy a credit pack", async () => {
      app.as({ id: person().id, email: null });
      const res = await post("/checkout/credits", { tier: "single" });
      expect(res.status).toBe(403);
      expect(((await res.json()) as any).code).toBe("account_required");
      expect(stripeState.sessionArgs).toBeNull();
    });
  });
});

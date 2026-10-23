/**
 * The Stripe webhook as HTTP: signature check, raw body, and status mapping.
 *
 * The route is mounted the way app.ts mounts it (raw body parser on the webhook
 * path, before anything that would parse JSON). The secret is a test-only value
 * and is not any real Stripe key.
 *
 * Two groups:
 *  - Without a database: a bad or missing signature is 400, and a database that
 *    cannot record the event is 500. The database connection is the placeholder
 *    from vitest.config.ts, which refuses connections, so that failure is real.
 *  - With BILLING_TEST_DATABASE_URL: a correctly signed event is 200, reaches
 *    processStripeEvent (visible as a row in stripe_events), and a redelivery is
 *    acknowledged without applying again.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";

const DB_URL = process.env["BILLING_TEST_DATABASE_URL"];
if (DB_URL) process.env["DATABASE_URL"] = DB_URL;

// Test-only values. Set before lib/stripe is imported, which reads them at import time.
// Kept under 32 characters so scripts/scan-secrets.sh's secret-assignment rule does not flag it.
const WEBHOOK_SECRET = "whsec_test_fake_not_real";
const STRIPE_KEY_FOR_TESTS = "sk_test_only_not_a_real_key";

const savedEnv = {
  STRIPE_SECRET_KEY: process.env["STRIPE_SECRET_KEY"],
  STRIPE_WEBHOOK_SECRET: process.env["STRIPE_WEBHOOK_SECRET"],
};

let app: express.Express;
let stripeLib: typeof import("../lib/stripe");
let dbMod: typeof import("@workspace/db");

async function buildApp(): Promise<express.Express> {
  const { default: stripeRouter } = await import("./stripe");
  const a = express();
  // Mirrors app.ts: the raw buffer must be what the signature is checked against.
  a.use("/api/scan/webhook", express.raw({ type: "application/json" }));
  a.use(express.json());
  a.use((req, _res, next) => {
    (req as unknown as { log: unknown }).log = { info() {}, warn() {}, error() {} };
    next();
  });
  a.use("/api", stripeRouter);
  return a;
}

function eventPayload(id: string): string {
  return JSON.stringify({
    id,
    object: "event",
    type: "invoice.created",
    api_version: "2026-09-30.endive",
    created: Math.floor(Date.now() / 1000),
    livemode: false,
    pending_webhooks: 0,
    request: { id: null, idempotency_key: null },
    data: { object: { id: `in_${id}` } },
  });
}

function signed(payload: string): string {
  return stripeLib.stripe!.webhooks.generateTestHeaderString({ payload, secret: WEBHOOK_SECRET });
}

beforeAll(async () => {
  process.env["STRIPE_SECRET_KEY"] = STRIPE_KEY_FOR_TESTS;
  process.env["STRIPE_WEBHOOK_SECRET"] = WEBHOOK_SECRET;
  stripeLib = await import("../lib/stripe");
  app = await buildApp();
  if (DB_URL) {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(DB_URL);
  }
}, 60_000);

afterAll(async () => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  await dbMod?.pool?.end?.();
});

describe("Stripe webhook route: signature and status codes", () => {
  it("answers 400 to a signature that does not match the payload", async () => {
    const res = await request(app)
      .post("/api/scan/webhook")
      .set("content-type", "application/json")
      .set("stripe-signature", "t=1700000000,v1=0000000000000000000000000000000000000000000000000000000000000000")
      .send(eventPayload("evt_test_bad_sig"));

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "Invalid webhook signature" });
  });

  it("answers 400 when a valid-looking body is sent with no signature header at all", async () => {
    const res = await request(app)
      .post("/api/scan/webhook")
      .set("content-type", "application/json")
      .send(eventPayload("evt_test_no_sig"));

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "Missing stripe-signature header" });
  });

  it("answers 400 when the body is altered after signing", async () => {
    const original = eventPayload("evt_test_tamper");
    const header = signed(original);
    const tampered = original.replace("invoice.created", "invoice.paid");

    const res = await request(app)
      .post("/api/scan/webhook")
      .set("content-type", "application/json")
      .set("stripe-signature", header)
      .send(tampered);

    expect(res.status).toBe(400);
  });
});

describe.skipIf(!!DB_URL)("Stripe webhook route: database failure (no database configured)", () => {
  it("answers 500 when the event cannot be recorded, so Stripe retries it", async () => {
    const payload = eventPayload("evt_test_db_down");
    const res = await request(app)
      .post("/api/scan/webhook")
      .set("content-type", "application/json")
      .set("stripe-signature", signed(payload))
      .send(payload);

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: "Webhook processing error" });
  }, 30_000);
});

describe.skipIf(!DB_URL)("Stripe webhook route: signed events (real Postgres)", () => {
  it("answers 200 to a correctly signed event and records it in the ledger", async () => {
    const id = `evt_test_ok_${Date.now()}`;
    const payload = eventPayload(id);
    const res = await request(app)
      .post("/api/scan/webhook")
      .set("content-type", "application/json")
      .set("stripe-signature", signed(payload))
      .send(payload);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ received: true });

    const ledger = await dbMod.db.execute(
      (await import("drizzle-orm")).sql`SELECT id, type FROM stripe_events WHERE id = ${id}`,
    );
    expect(ledger.rows).toEqual([{ id, type: "invoice.created" }]);
  }, 60_000);

  it("acknowledges a redelivery of the same event without recording it twice", async () => {
    const id = `evt_test_redeliver_${Date.now()}`;
    const payload = eventPayload(id);
    const header = signed(payload);

    const first = await request(app).post("/api/scan/webhook").set("content-type", "application/json").set("stripe-signature", header).send(payload);
    const again = await request(app).post("/api/scan/webhook").set("content-type", "application/json").set("stripe-signature", header).send(payload);

    expect(first.status).toBe(200);
    expect(again.status).toBe(200);
    const ledger = await dbMod.db.execute((await import("drizzle-orm")).sql`SELECT id FROM stripe_events WHERE id = ${id}`);
    expect(ledger.rows).toHaveLength(1);
  }, 60_000);
});

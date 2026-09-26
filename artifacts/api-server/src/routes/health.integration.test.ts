/**
 * /healthz/deep against a REAL Postgres, so the queries are proven, not just typed.
 * Runs only with HEALTH_TEST_DATABASE_URL (a disposable database; it truncates scans).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";

const URL_ = process.env["HEALTH_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

let app: express.Express;
let dbMod: typeof import("@workspace/db");

suite("/healthz/deep (real Postgres)", () => {
  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    const { sql } = await import("drizzle-orm");
    await dbMod.db.execute(sql`TRUNCATE scans, monitor_subscriptions, monitor_pulse_checks CASCADE`);
    const { default: health } = await import("./health");
    app = express();
    app.use(health);
  }, 60_000);

  afterAll(async () => {
    await dbMod?.pool?.end?.();
  });

  it("is 200 with an empty, healthy database", async () => {
    const res = await request(app).get("/healthz/deep");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "ok", checks: { database: "ok", worker: "ok" } });
  });

  it("is 503 when a scan has sat queued past the stall window", async () => {
    const { scansTable } = dbMod;
    await dbMod.db.insert(scansTable).values({
      userId: "u1",
      userEmail: "u1@example.com",
      targetUrl: "https://example.com",
      tier: "deep",
      status: "queued",
      startedAt: new Date(Date.now() - 30 * 60_000),
    } as never);
    const res = await request(app).get("/healthz/deep");
    expect(res.status).toBe(503);
    expect(res.body.checks.worker).toBe("stalled");
  });
});

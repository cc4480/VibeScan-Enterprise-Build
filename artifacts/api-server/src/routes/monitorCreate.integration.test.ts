/**
 * POST /monitor/subscriptions against a REAL Postgres: the plan limit and the duplicate
 * check must hold when creates for one user arrive together. Skips unless a throwaway
 * database is supplied (see freeTrial.integration.test.ts).
 */
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const LIMIT = 2;

vi.mock("../lib/ssrfGuard", () => ({ checkScanTarget: async () => ({ ok: true }) }));
vi.mock("../lib/queue", () => ({ enqueueScan: async () => "job" }));
vi.mock("../lib/entitlements", () => ({
  monitorEntitlement: async () => ({ monitoringActive: true, urlLimit: LIMIT, reason: "free" }),
}));
// A plan holder pays nothing, which keeps the billing side out of the way; the lock is what is under test.
vi.mock("../lib/billing", async (importOriginal) => {
  const real = await importOriginal<typeof import("../lib/billing")>();
  return {
    ...real,
    hasLivePlan: async () => true,
    chargeScan: async () => "included",
    refundCharge: async () => {},
    refundFailedScan: async () => {},
  };
});

suite("monitor create under concurrency (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let drizzle: typeof import("drizzle-orm");
  let handler: (req: unknown, res: unknown) => Promise<void>;

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    drizzle = await import("drizzle-orm");
    const { registerMonitorCreate } = await import("./monitorCreate");
    let captured: ((req: unknown, res: unknown) => Promise<void>) | undefined;
    registerMonitorCreate({
      post: (_path: string, ...handlers: unknown[]) => {
        captured = handlers[handlers.length - 1] as typeof captured;
      },
    } as never);
    handler = captured!;
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });

  function create(userId: string, targetUrl: string) {
    const res = { statusCode: 200, body: null as unknown, status(c: number) { this.statusCode = c; return this; }, json(b: unknown) { this.body = b; return this; } };
    const req = { body: { targetUrl }, isAuthenticated: () => true, user: { id: userId, email: "owner@example.com" }, log: { error() {}, info() {} } };
    return handler(req, res).then(() => res);
  }

  it("does not let parallel creates exceed the plan's site limit", async () => {
    const userId = `mc-limit-${Date.now()}`;
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, i) => create(userId, `https://site-${i}.example.com/`)),
    );

    expect(results.filter((r) => r.statusCode === 201)).toHaveLength(LIMIT);
    expect(results.filter((r) => r.statusCode === 403)).toHaveLength(6 - LIMIT);
    const rows = await dbMod.db
      .select({ id: dbMod.monitorSubscriptionsTable.id })
      .from(dbMod.monitorSubscriptionsTable)
      .where(drizzle.and(drizzle.eq(dbMod.monitorSubscriptionsTable.userId, userId), drizzle.eq(dbMod.monitorSubscriptionsTable.status, "active")));
    expect(rows).toHaveLength(LIMIT);
  });

  it("does not create the same monitor twice when parallel creates name one URL", async () => {
    const userId = `mc-dup-${Date.now()}`;
    const results = await Promise.all(Array.from({ length: 4 }, () => create(userId, "https://same.example.com/")));

    expect(results.filter((r) => r.statusCode === 201)).toHaveLength(1);
    expect(results.filter((r) => r.statusCode === 409)).toHaveLength(3);
    const rows = await dbMod.db
      .select({ id: dbMod.monitorSubscriptionsTable.id })
      .from(dbMod.monitorSubscriptionsTable)
      .where(drizzle.eq(dbMod.monitorSubscriptionsTable.userId, userId));
    expect(rows).toHaveLength(1);
  });
});

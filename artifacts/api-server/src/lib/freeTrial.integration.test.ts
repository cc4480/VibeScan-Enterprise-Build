/**
 * The free allowance against a REAL Postgres: the race is between concurrent transactions, which a
 * mocked db cannot reproduce. Skips unless a throwaway database is supplied — see
 * apiTokens.integration.test.ts.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("free scan allowance (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let trial: typeof import("./freeTrial");

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    trial = await import("./freeTrial");
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });

  it("lets only the allowance through when requests all counted the same rows", async () => {
    const { db, usersTable, scansTable } = dbMod;
    const [u] = await db.insert(usersTable).values({ email: null }).returning({ id: usersTable.id });
    const attempt = () =>
      trial.insertScanRow({ userId: u!.id, userEmail: "", targetUrl: "https://example.com", tier: "deep", status: "paid", paidWith: "free" });

    const results = await Promise.allSettled(Array.from({ length: trial.FREE_TRIAL_SCAN_LIMIT + 5 }, attempt));

    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(trial.FREE_TRIAL_SCAN_LIMIT);
    for (const r of results) {
      if (r.status === "rejected") expect(r.reason).toBeInstanceOf(trial.TrialExhaustedError);
    }
    expect(await trial.trialScansUsedBy(u!.id)).toBe(trial.FREE_TRIAL_SCAN_LIMIT);
    await db.delete(scansTable).where((await import("drizzle-orm")).eq(scansTable.userId, u!.id));
  });
});

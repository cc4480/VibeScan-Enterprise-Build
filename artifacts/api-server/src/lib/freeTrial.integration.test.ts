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

  it("holds the daily limit when requests arrive together", async () => {
    const { db, usersTable, scansTable } = dbMod;
    const { eq } = await import("drizzle-orm");
    const [u] = await db.insert(usersTable).values({ email: null }).returning({ id: usersTable.id });
    const attempt = () =>
      trial.insertScanRow({ userId: u!.id, userEmail: "", targetUrl: "https://example.com", tier: "deep", status: "paid", paidWith: "credit" }, { dailyMax: 4 });
    const results = await Promise.allSettled(Array.from({ length: 10 }, attempt));
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(4);
    for (const r of results) if (r.status === "rejected") expect(r.reason).toBeInstanceOf(trial.DailyLimitError);
    await db.delete(scansTable).where(eq(scansTable.userId, u!.id));
  });

  it("remembers free scans used by an account that was then deleted", async () => {
    const { db, usersTable, scansTable } = dbMod;
    const { eq } = await import("drizzle-orm");
    const email = `carry-${Date.now()}@example.com`;
    const [a] = await db.insert(usersTable).values({ email }).returning({ id: usersTable.id });
    for (let i = 0; i < 2; i++) {
      await trial.insertScanRow({ userId: a!.id, userEmail: email, targetUrl: "https://example.com", tier: "deep", status: "paid", paidWith: "free" });
    }
    await db.transaction((tx) => trial.carryTrialUsage(tx, a!.id, email));
    await db.delete(scansTable).where(eq(scansTable.userId, a!.id));
    await db.delete(usersTable).where(eq(usersTable.id, a!.id));

    const [b] = await db.insert(usersTable).values({ email }).returning({ id: usersTable.id });
    expect(await trial.trialScansUsedBy(b!.id)).toBe(2);
    await db.delete(usersTable).where(eq(usersTable.id, b!.id));
  });
});

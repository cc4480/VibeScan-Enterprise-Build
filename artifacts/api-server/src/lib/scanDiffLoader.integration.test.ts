/**
 * Which earlier scan a report is compared with, against a REAL Postgres. Choosing the
 * wrong one produces a plausible but false "what changed", so the choice is tested
 * against real rows. Skips unless a throwaway database is supplied
 * (see billing.integration.test.ts); run it with --no-file-parallelism.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const test = (name: string, status = "ran") => ({ group: "g", name, status, findings: 0, durationMs: 1 });
const vuln = (name: string) => ({ name, severity: "high", category: "HTTP Security", evidence: "" });
const CSP = "Missing Content-Security-Policy (CSP)";

suite("scanDiffLoader (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let loader: typeof import("./scanDiffLoader");
  let sql: typeof import("drizzle-orm").sql;
  let n = 0;

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    loader = await import("./scanDiffLoader");
    sql = (await import("drizzle-orm")).sql;
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });
  beforeEach(async () => { await dbMod.db.execute(sql`TRUNCATE reports, scans CASCADE`); });

  /** A finished scan and its report, `daysAgo` days old. */
  async function report(userId: string, targetUrl: string, daysAgo: number, data: unknown, credentialed = false) {
    const { db, scansTable, reportsTable } = dbMod;
    const at = new Date(Date.now() - daysAgo * 86_400_000);
    const [scan] = await db
      .insert(scansTable)
      .values({ userId, userEmail: `u${++n}@example.com`, targetUrl, tier: "deep", status: "complete", ...(credentialed ? { credentialsAuthorizedAt: at } : {}) })
      .returning({ id: scansTable.id });
    await db.insert(reportsTable).values({ scanId: scan!.id, userId, targetUrl, tier: "deep", scannedAt: at, duration: 1, data: data as never });
    return { scanId: scan!.id, scannedAt: at, data, targetUrl };
  }
  const scanOf = (vulns: unknown[], tests: unknown[] = [test("response headers and cookies")]) => ({ vulnerabilities: vulns, tests });

  it("compares with the most recent earlier scan of the same site, and says what was fixed", async () => {
    await report("u1", "https://a.example/", 9, scanOf([vuln(CSP)]));
    await report("u1", "https://a.example/", 3, scanOf([vuln(CSP), vuln("Missing Referrer-Policy Header")]));
    const now = await report("u1", "https://a.example/", 0, scanOf([vuln(CSP)]));

    const c = await loader.changesForReport("u1", now);
    // Against the scan three days ago, not the one nine days ago.
    expect(c?.fixed.map((x) => x.name)).toEqual(["Missing Referrer-Policy Header"]);
    expect(c?.unchanged).toBe(1);
  });

  it("returns null for a first scan of a site", async () => {
    const now = await report("u1", "https://first.example/", 0, scanOf([vuln(CSP)]));
    expect(await loader.changesForReport("u1", now)).toBeNull();
  });

  it("never compares with a different site, nor with another user's scans", async () => {
    await report("u1", "https://other-site.example/", 3, scanOf([vuln(CSP)]));
    await report("u2", "https://a.example/", 3, scanOf([vuln(CSP)]));
    const now = await report("u1", "https://a.example/", 0, scanOf([]));
    expect(await loader.changesForReport("u1", now)).toBeNull();
  });

  it("treats the same site written differently as the same site", async () => {
    await report("u1", "HTTPS://A.Example/docs/", 3, scanOf([vuln(CSP)]));
    const now = await report("u1", "https://a.example/docs", 0, scanOf([]));
    const c = await loader.changesForReport("u1", now);
    expect(c?.fixed).toHaveLength(1);
  });

  it("does not use a scan made later than the report being read", async () => {
    const old = await report("u1", "https://a.example/", 5, scanOf([vuln(CSP)]));
    await report("u1", "https://a.example/", 0, scanOf([]));
    // Reading the OLD report must not compare it with the newer one.
    expect(await loader.changesForReport("u1", old)).toBeNull();
  });

  it("flags a login used on one scan and not the other", async () => {
    await report("u1", "https://a.example/", 3, scanOf([]), true);
    const now = await report("u1", "https://a.example/", 0, scanOf([]), false);
    expect((await loader.changesForReport("u1", now))?.differentAccess).toBe(true);
  });

  it("does not call a finding fixed when its test did not run this time", async () => {
    await report("u1", "https://a.example/", 3, scanOf([vuln("CORS — Origin Reflected Without Credentials")], [test("response headers and cookies"), test("active CORS")]));
    const now = await report("u1", "https://a.example/", 0, scanOf([], [test("response headers and cookies"), test("active CORS", "skipped")]));
    const c = await loader.changesForReport("u1", now);
    expect(c?.fixed).toEqual([]);
    expect(c?.notRechecked).toHaveLength(1);
  });
});

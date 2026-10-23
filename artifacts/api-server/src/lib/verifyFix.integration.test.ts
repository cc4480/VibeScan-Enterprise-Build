/**
 * "I fixed this" against a REAL Postgres: who may verify what, the limits, what a
 * verdict says, and what happens when the scan behind it fails. Skips unless a
 * throwaway database is supplied (see billing.integration.test.ts); run with
 * --no-file-parallelism alongside the other integration suites.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const t = (name: string, status = "ran") => ({ group: "g", name, status, findings: 0, durationMs: 1 });
const CSP = "Missing Content-Security-Policy (CSP)";
const CORS = "CORS — Origin Reflected Without Credentials";
const finding = (id: string, name: string, category = "HTTP Security") => ({ id, name, severity: "high", category, evidence: "", description: "d", solution: "s" });
const HEADERS = "response headers and cookies";

suite("verify a fix (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let verify: typeof import("./verifyFix");
  let sql: typeof import("drizzle-orm").sql;
  let eq: typeof import("drizzle-orm").eq;
  let n = 0;

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    verify = await import("./verifyFix");
    ({ sql, eq } = await import("drizzle-orm"));
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });
  beforeEach(async () => {
    await dbMod.db.execute(sql`TRUNCATE finding_verifications, reports, scans CASCADE`);
  });

  async function reportWith(userId: string, vulns: unknown[], tests: unknown[], credentialed = false) {
    const { db, scansTable, reportsTable } = dbMod;
    const [scan] = await db.insert(scansTable).values({ userId, userEmail: `u${++n}@example.com`, targetUrl: "https://a.example/", tier: "deep", status: "complete", ...(credentialed ? { credentialsAuthorizedAt: new Date() } : {}) }).returning({ id: scansTable.id });
    const [r] = await db.insert(reportsTable).values({ scanId: scan!.id, userId, targetUrl: "https://a.example/", tier: "deep", duration: 1, data: { vulnerabilities: vulns, tests } as never }).returning({ id: reportsTable.id });
    return r!.id;
  }
  const start = (userId: string, reportId: string, findingId: string) => verify.startVerification({ userId, userEmail: "u@example.com", reportId, findingId });
  const rowsOf = async () => dbMod.db.select().from(dbMod.findingVerificationsTable);
  /** The jobs the real queue holds for this test's verification scans (the scans table is emptied before each test). */
  const queuedJobs = async () => {
    const r = await dbMod.db.execute(sql`select data from pgboss.job where name = 'scan-job' and data->>'scanId' in (select id::text from scans where origin = 'verify')`);
    return r.rows.map((row) => (row as { data: Record<string, unknown> }).data);
  };

  describe("who may verify what", () => {
    it("refuses another user's report and an id that is not in the report, with the same answer", async () => {
      const rid = await reportWith("u1", [finding("f1", CSP)], [t(HEADERS)]);
      const other = await start("u2", rid, "f1");
      const missing = await start("u1", rid, "nope");
      expect(other).toMatchObject({ ok: false, status: 404 });
      expect(missing).toMatchObject({ ok: false, status: 404 });
    });

    it("does not treat a scan-coverage notice as a finding to fix", async () => {
      const rid = await reportWith("u1", [finding("n1", "Active security testing was skipped", "Scan Coverage")], [t(HEADERS)]);
      expect(await start("u1", rid, "n1")).toMatchObject({ ok: false, status: 404 });
    });

    it("says a login-only finding cannot be re-checked this way, and why", async () => {
      const rid = await reportWith("u1", [finding("f1", CSP)], [t(HEADERS)], true);
      const r = await start("u1", rid, "f1");
      expect(r).toMatchObject({ ok: false, status: 409, code: "needs_login" });
    });
  });

  describe("starting one", () => {
    it("queues a free, hidden scan of the same site and records a pending verification", async () => {
      const rid = await reportWith("u1", [finding("f1", CSP)], [t(HEADERS)]);
      const r = await start("u1", rid, "f1");
      expect(r.ok).toBe(true);
      const { db, scansTable } = dbMod;
      const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, (r as { scanId: string }).scanId));
      expect(scan).toMatchObject({ origin: "verify", status: "queued", targetUrl: "https://a.example/", paidWith: null });
      expect((await rowsOf())[0]).toMatchObject({ verdict: "pending", findingId: "f1", userId: "u1" });
      expect((await queuedJobs())[0]).toMatchObject({ scanId: scan!.id, verificationId: (r as { verificationId: string }).verificationId });
    });

    it("does not start a second check while one is pending: it returns the first", async () => {
      const rid = await reportWith("u1", [finding("f1", CSP)], [t(HEADERS)]);
      const a = await start("u1", rid, "f1");
      const b = await start("u1", rid, "f1");
      expect(b).toEqual(a);
      expect(await queuedJobs()).toHaveLength(1);
    });

    it("stops at ten a day", async () => {
      const ids = Array.from({ length: 11 }, (_, i) => finding(`f${i}`, CSP + i));
      const rid = await reportWith("u1", ids, [t(HEADERS)]);
      for (let i = 0; i < 10; i++) expect((await start("u1", rid, `f${i}`)).ok, `#${i}`).toBe(true);
      expect(await start("u1", rid, "f10")).toMatchObject({ ok: false, status: 429, code: "rate_limited" });
    });

    it("holds the ten-a-day line when checks for one account arrive together", async () => {
      const ids = Array.from({ length: 15 }, (_, i) => finding(`p${i}`, CSP + "p" + i));
      const rid = await reportWith("u-par", ids, [t(HEADERS)]);
      const outcomes = await Promise.all(ids.map((f) => start("u-par", rid, f.id)));

      expect(outcomes.filter((o) => o.ok)).toHaveLength(10);
      expect(outcomes.filter((o) => !o.ok && o.status === 429)).toHaveLength(5);
      expect(await rowsOf()).toHaveLength(10);
    });

    // The queue really is down: pg-boss is stopped, then started again.
    it("fails cleanly, leaving nothing pending, when the queue is down", async () => {
      const { getBoss } = await import("./queue");
      const boss = await getBoss();
      const rid = await reportWith("u1", [finding("f1", CSP)], [t(HEADERS)]);
      await boss.stop({ graceful: false });
      try {
        expect(await start("u1", rid, "f1")).toMatchObject({ ok: false, status: 503 });
        expect((await rowsOf())[0]).toMatchObject({ verdict: "failed" });
      } finally {
        await boss.start();
      }
      expect((await start("u1", rid, "f1")).ok).toBe(true);
    }, 60_000);
  });

  describe("the verdict", () => {
    async function verdict(before: { vulns: unknown[]; tests: unknown[] }, after: { vulns: unknown[]; tests: unknown[] }, findingName = CSP) {
      const rid = await reportWith("u1", before.vulns.length ? before.vulns : [finding("f1", findingName)], before.tests);
      const r = (await start("u1", rid, "f1")) as { verificationId: string };
      return { rid, r, verdict: await verify.completeVerification(r.verificationId, { vulnerabilities: after.vulns, tests: after.tests }) };
    }

    it("fixed: gone, and its test ran again", async () => {
      const { verdict: v, r } = await verdict({ vulns: [finding("f1", CSP)], tests: [t(HEADERS)] }, { vulns: [], tests: [t(HEADERS)] });
      expect(v).toBe("fixed");
      expect((await rowsOf()).find((x) => x.id === r.verificationId)).toMatchObject({ verdict: "fixed" });
      expect((await rowsOf())[0]!.completedAt).not.toBeNull();
    });

    it("still_present: found again", async () => {
      expect((await verdict({ vulns: [finding("f1", CSP)], tests: [t(HEADERS)] }, { vulns: [finding("z", CSP)], tests: [t(HEADERS)] })).verdict).toBe("still_present");
    });

    it("not_rechecked, never fixed: gone because its test did not run", async () => {
      const r = await verdict(
        { vulns: [finding("f1", CORS, "CORS Misconfiguration")], tests: [t(HEADERS), t("active CORS")] },
        { vulns: [], tests: [t(HEADERS), t("active CORS", "skipped")] },
      );
      expect(r.verdict).toBe("not_rechecked");
    });

    it("failed, not a guess, when the report it was judged against is gone", async () => {
      const rid = await reportWith("u1", [finding("f1", CSP)], [t(HEADERS)]);
      const r = (await start("u1", rid, "f1")) as { verificationId: string };
      await dbMod.db.execute(sql`DELETE FROM reports`);
      expect(await verify.completeVerification(r.verificationId, { vulnerabilities: [], tests: [t(HEADERS)] })).toBe("failed");
    });

    it("returns null for a verification that does not exist", async () => {
      expect(await verify.completeVerification("00000000-0000-4000-8000-000000000000", {})).toBeNull();
    });
  });

  describe("when the scan fails", () => {
    it("fails the pending verification for that scan, and no other", async () => {
      const rid = await reportWith("u1", [finding("f1", CSP), finding("f2", CSP + "2")], [t(HEADERS)]);
      const a = (await start("u1", rid, "f1")) as { scanId: string };
      const b = (await start("u1", rid, "f2")) as { scanId: string };
      await verify.failVerificationForScan(a.scanId);
      const rows = await rowsOf();
      expect(rows.find((x) => x.scanId === a.scanId)?.verdict).toBe("failed");
      expect(rows.find((x) => x.scanId === b.scanId)?.verdict).toBe("pending");
      await expect(verify.failVerificationForScan("00000000-0000-4000-8000-000000000000")).resolves.toBeUndefined();
    });

    it("does not overwrite a verdict that already arrived", async () => {
      const rid = await reportWith("u1", [finding("f1", CSP)], [t(HEADERS)]);
      const r = (await start("u1", rid, "f1")) as { scanId: string; verificationId: string };
      await verify.completeVerification(r.verificationId, { vulnerabilities: [], tests: [t(HEADERS)] });
      await verify.failVerificationForScan(r.scanId);
      expect((await rowsOf())[0]!.verdict).toBe("fixed");
    });
  });

  describe("reading them back", () => {
    it("gives the most recent verification of each finding, for the owner only", async () => {
      const rid = await reportWith("u1", [finding("f1", CSP)], [t(HEADERS)]);
      const first = (await start("u1", rid, "f1")) as { verificationId: string };
      await verify.completeVerification(first.verificationId, { vulnerabilities: [finding("z", CSP)], tests: [t(HEADERS)] });
      const second = (await start("u1", rid, "f1")) as { verificationId: string };
      await verify.completeVerification(second.verificationId, { vulnerabilities: [], tests: [t(HEADERS)] });

      const mine = await verify.latestVerifications("u1", rid);
      expect(mine).toHaveLength(1);
      expect(mine[0]).toMatchObject({ findingId: "f1", verdict: "fixed" });
      expect(await verify.latestVerifications("u2", rid)).toEqual([]);
    });
  });
});

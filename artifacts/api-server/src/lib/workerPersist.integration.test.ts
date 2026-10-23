/**
 * The end of a scan job against a REAL Postgres (BILLING_TEST_DATABASE_URL): the report is stored and the scan
 * closed, or, when the report cannot be stored, the scan is failed and refunded. Both paths clear the stored
 * logins; the failure path must never throw out of the job; and nothing that happens after the report is saved
 * may undo it.
 *
 * "The report cannot be stored" is a real Postgres rejection (a duration past the integer column), not a staged one.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Writable } from "node:stream";
import pino from "pino";
import { dbSuiteOf, useRealDb, openDb, makeUser, uniqueEmail } from "./realDb.testkit";

useRealDb();
// A test must never send real mail.
delete process.env["RESEND_API_KEY"];

const headersRan = { group: "passive", name: "response headers and cookies", status: "ran", findings: 0, durationMs: 1 };
const finding = { id: "f1", name: "Missing Content-Security-Policy (CSP)", severity: "high", category: "HTTP Security", evidence: "", description: "d", solution: "s" };

dbSuiteOf(describe)("persistReport and refundIfPaid (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let persist: typeof import("./workerPersist");
  let verify: typeof import("./verifyFix");
  let billing: typeof import("./credits");
  let userId: string;
  const lines: string[] = [];
  const log = pino({ level: "info" }, new Writable({ write(chunk, _enc, cb) { lines.push(String(chunk)); cb(); } }));

  /** A scan row mid-job: it holds sealed logins and, optionally, a paid credit. */
  async function scan(paidWith: "credit" | null = null) {
    const [s] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({
        userId, userEmail: uniqueEmail("persist"), targetUrl: "https://persist.example/", tier: "deep", status: "scanning",
        credentialsEncrypted: "sealed-1", secondaryCredentialsEncrypted: "sealed-2", ...(paidWith ? { paidWith } : {}),
      })
      .returning({ id: dbMod.scansTable.id });
    return s!.id;
  }
  const scanRow = async (id: string) => (await dbMod.db.select().from(dbMod.scansTable).where(eq(dbMod.scansTable.id, id)))[0]!;
  const reportsOf = (id: string) => dbMod.db.select().from(dbMod.reportsTable).where(eq(dbMod.reportsTable.scanId, id));
  const input = (scanId: string, over: Record<string, unknown> = {}) => ({
    scanId, userId, targetUrl: "https://persist.example/", tier: "deep",
    scanResult: { finalUrl: "https://persist.example/final", requestDurationMs: 42, vulnerabilities: [] } as never,
    tests: [] as never, reportData: { summary: {}, vulnerabilities: [], tests: [headersRan] } as never, riskScore: 12 as never, grade: "B" as never,
    intercepted: false as never, severityCounts: {} as never, executiveSummary: "s" as never, log: log as never,
    ...over,
  });

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    persist = await import("./workerPersist");
    verify = await import("./verifyFix");
    billing = await import("./credits");
    userId = await makeUser(dbMod, "persist-owner");
    await dbMod.db.insert(dbMod.creditsTable).values({ userId, balance: 0 });
  }, 60_000);

  afterAll(async () => {
    const { eq: eqq } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.findingVerificationsTable).where(eqq(dbMod.findingVerificationsTable.userId, userId));
    await dbMod.db.delete(dbMod.reportsTable).where(eqq(dbMod.reportsTable.userId, userId));
    await dbMod.db.delete(dbMod.scansTable).where(eqq(dbMod.scansTable.userId, userId));
    await dbMod.db.delete(dbMod.creditsTable).where(eqq(dbMod.creditsTable.userId, userId));
    await dbMod.db.delete(dbMod.usersTable).where(eqq(dbMod.usersTable.id, userId));
    await dbMod?.pool?.end?.();
  });

  describe("persistReport: the report is saved", () => {
    it("stores the report under the final URL, completes the scan, and clears the stored logins", async () => {
      const id = await scan("credit");
      const before = await billing.creditBalance(userId);
      await persist.persistReport(input(id));
      const [report] = await reportsOf(id);
      expect(report).toMatchObject({ scanId: id, userId, targetUrl: "https://persist.example/final", tier: "deep", duration: 42 });
      expect(report!.data).toMatchObject({ summary: {} });
      const row = await scanRow(id);
      expect(row).toMatchObject({ status: "complete", credentialsEncrypted: null, secondaryCredentialsEncrypted: null });
      expect(row.completedAt).toBeInstanceOf(Date);
      expect(await billing.creditBalance(userId)).toBe(before); // a finished scan is not refunded
    });

    it("falls back to the requested URL when the scan never learned a final one", async () => {
      const id = await scan();
      await persist.persistReport(input(id, { scanResult: { finalUrl: "", requestDurationMs: 1, vulnerabilities: [] } }));
      expect((await reportsOf(id))[0]).toMatchObject({ targetUrl: "https://persist.example/" });
    });

    it("judges a re-check against the stored report only when the job is one", async () => {
      // A report holding one finding, then a real re-check of it.
      const priorScan = await scan();
      await persist.persistReport(input(priorScan, { reportData: { summary: {}, vulnerabilities: [finding], tests: [headersRan] } }));
      const prior = (await reportsOf(priorScan))[0]!;
      const started = await verify.startVerification({ userId, userEmail: "u@example.com", reportId: prior.id, findingId: "f1" });
      if (!started.ok) throw new Error(`could not start the re-check: ${started.message}`);

      const verdictOf = async () => (await dbMod.db.select().from(dbMod.findingVerificationsTable).where(eq(dbMod.findingVerificationsTable.id, started.verificationId)))[0]!.verdict;
      // An ordinary job for some other scan leaves the pending re-check alone.
      await persist.persistReport(input(await scan()));
      expect(await verdictOf()).toBe("pending");
      // The re-check's own job, with the finding gone and its check run again, judges it fixed.
      await persist.persistReport(input(started.scanId, { verificationId: started.verificationId }));
      expect(await verdictOf()).toBe("fixed");
    });

    it("does not undo a saved report when what comes after it cannot be recorded", async () => {
      // A re-check and a monitor that do not exist: the steps after the save have nothing to act on.
      const id = await scan("credit");
      const before = await billing.creditBalance(userId);
      await persist.persistReport(input(id, {
        verificationId: "00000000-0000-4000-8000-000000000000",
        monitorSubscriptionId: "00000000-0000-4000-8000-000000000001",
      }));
      expect(await reportsOf(id)).toHaveLength(1);
      expect((await scanRow(id)).status).toBe("complete");
      expect(await billing.creditBalance(userId)).toBe(before);
    });
  });

  describe("persistReport: the report cannot be stored", () => {
    // 5,000,000,000 ms does not fit the integer duration column, so Postgres refuses the insert.
    const overflow = { finalUrl: "", requestDurationMs: 5_000_000_000, vulnerabilities: [] };

    it("fails the scan, clears the stored logins, and refunds the credit, without throwing", async () => {
      const id = await scan("credit");
      const before = await billing.creditBalance(userId);
      await expect(persist.persistReport(input(id, { scanResult: overflow }))).resolves.toBeUndefined();
      expect(await reportsOf(id)).toHaveLength(0);
      const row = await scanRow(id);
      expect(row).toMatchObject({ status: "failed", error: "Failed to save report — please contact support", credentialsEncrypted: null, secondaryCredentialsEncrypted: null });
      expect(await billing.creditBalance(userId)).toBe(before + 1);
    });

    it("fails a pending re-check along with the scan", async () => {
      const priorScan = await scan();
      await persist.persistReport(input(priorScan, { reportData: { summary: {}, vulnerabilities: [finding], tests: [headersRan] } }));
      const prior = (await reportsOf(priorScan))[0]!;
      const started = await verify.startVerification({ userId, userEmail: "u@example.com", reportId: prior.id, findingId: "f1" });
      if (!started.ok) throw new Error(`could not start the re-check: ${started.message}`);
      await persist.persistReport(input(started.scanId, { scanResult: overflow, verificationId: started.verificationId }));
      const [v] = await dbMod.db.select().from(dbMod.findingVerificationsTable).where(eq(dbMod.findingVerificationsTable.id, started.verificationId));
      expect(v!.verdict).toBe("failed");
    });
  });

  describe("refundIfPaid", () => {
    it("logs what was given back, and nothing when nothing was", async () => {
      const id = await scan("credit");
      lines.length = 0;
      await persist.refundIfPaid(id, log);
      expect(lines.join("")).toContain("Refunded the payment for a failed scan");
      expect(lines.join("")).toContain('"refunded":"credit"');
      lines.length = 0;
      await persist.refundIfPaid(id, log); // already given back: idempotent
      expect(lines.join("")).not.toContain("Refunded the payment");
    });

    it("never throws, and says it needs manual credit, when the refund itself cannot run", async () => {
      lines.length = 0;
      // Not a UUID, so Postgres rejects the lookup: a real failure of the refund.
      await expect(persist.refundIfPaid("not-a-uuid", log)).resolves.toBeUndefined();
      expect(lines.join("")).toContain("needs manual credit");
    });
  });
});

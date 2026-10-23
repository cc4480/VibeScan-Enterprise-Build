/**
 * The scan job, run for real against a REAL Postgres (BILLING_TEST_DATABASE_URL) and a real web server on
 * loopback: the real scanner, TLS check, reconnaissance, analysis stage and report storage.
 *
 * A scan whose owner deleted their account must stop, and it must stop before the step that costs money.
 * Deleting an account removes its scan rows (routes/account.ts) before the user row, and reports.scan_id carries the
 * only foreign key involved, so a job whose scan id no longer resolves can never store a report. Before the guards
 * these tests cover, such a job ran the entire scan and then paid for an AI call, failing only at the insert.
 *
 * Each abandonment test also asserts the job returned, otherwise "no report" would also pass for a job that
 * crashed on the line before. The AI call itself is not observable from here (no key is configured, so none is
 * ever made), which is why the guard is shown by the job stopping with nothing stored.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { randomUUID } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb, makeUser, uniqueEmail } from "./realDb.testkit";

useRealDb();
// No AI key and no SSL Labs: the job's default, and nothing here may spend money or call a third party.
delete process.env["DEEPSEEK_API_KEY"];
delete process.env["SSLLABS_ENABLED"];
delete process.env["RESEND_API_KEY"];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

dbSuiteOf(describe)("processScanJob (real Postgres, real scanner)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let work: typeof import("./worker");
  let site: http.Server;
  let siteUrl: string;
  let userId: string;
  const scanIds: string[] = [];

  /** A queued scan row for the local site, as the scan-creation route leaves it. */
  async function queuedScan() {
    const [s] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId, userEmail: uniqueEmail("worker"), targetUrl: siteUrl, tier: "deep", status: "queued" })
      .returning({ id: dbMod.scansTable.id });
    scanIds.push(s!.id);
    return s!.id;
  }
  const jobFor = (scanId: string) => ({ data: { scanId, userId, targetUrl: siteUrl, tier: "deep" } }) as never;
  const reportsOf = (scanId: string) => dbMod.db.select().from(dbMod.reportsTable).where(eq(dbMod.reportsTable.scanId, scanId));
  const scanRow = async (scanId: string) => (await dbMod.db.select().from(dbMod.scansTable).where(eq(dbMod.scansTable.id, scanId)))[0];

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    work = await import("./worker");
    userId = await makeUser(dbMod, "worker-owner");
    site = http.createServer((req, res) => {
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(req.url === "/" ? "<!doctype html><title>Scan target</title><h1>hello</h1>" : "<!doctype html><title>not found</title>");
    });
    await new Promise<void>((r) => site.listen(0, "127.0.0.1", () => r()));
    siteUrl = `http://127.0.0.1:${(site.address() as AddressInfo).port}/`;
  }, 60_000);

  afterAll(async () => {
    site?.close();
    const { inArray } = await import("drizzle-orm");
    if (scanIds.length) {
      await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.scanId, scanIds));
      await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.id, scanIds));
    }
    await dbMod.db.delete(dbMod.usersTable).where(eq(dbMod.usersTable.id, userId));
    await dbMod?.pool?.end?.();
  });

  describe("abandoned when the scan row is gone", () => {
    it("does no scanning at all when the row was deleted while the job sat in the queue", async () => {
      // Step 1's update matches nothing: the account was deleted before a worker slot freed up.
      const gone = randomUUID();
      const started = Date.now();
      await expect(work.processScanJob(jobFor(gone))).resolves.toBeUndefined();
      expect(Date.now() - started).toBeLessThan(3000); // a real scan of any site takes far longer than this
      expect(await reportsOf(gone)).toHaveLength(0);
      expect(await scanRow(gone)).toBeUndefined();
    });

    it("refuses to carry on to a stored report when the row disappears mid-scan", async () => {
      // Step 1 finds the row, so the scan runs; the owner then deletes the account while it is in flight.
      const id = await queuedScan();
      let finished = false;
      const running = work.processScanJob(jobFor(id)).finally(() => { finished = true; });
      await sleep(400);
      expect(finished).toBe(false); // the delete below really does land mid-scan
      await dbMod.db.delete(dbMod.scansTable).where(eq(dbMod.scansTable.id, id));
      await expect(running).resolves.toBeUndefined();
      expect(await reportsOf(id)).toHaveLength(0);
      expect(await scanRow(id)).toBeUndefined();
    }, 240_000);

    it("does not run a scan the stuck-scan cleanup already failed and refunded", async () => {
      const id = await queuedScan();
      await dbMod.db.update(dbMod.scansTable).set({ status: "failed", error: "reaped" }).where(eq(dbMod.scansTable.id, id));
      await expect(work.processScanJob(jobFor(id))).resolves.toBeUndefined();
      expect(await reportsOf(id)).toHaveLength(0);
      expect((await scanRow(id))?.status).toBe("failed");
    });
  });

  describe("a healthy job", () => {
    it("runs the whole job when the row is present throughout: a report is stored and the scan completes", async () => {
      const id = await queuedScan();
      await work.processScanJob(jobFor(id));
      const [report] = await reportsOf(id);
      expect(report).toBeDefined();
      expect(report!.userId).toBe(userId);
      const data = report!.data as any;
      expect(typeof data.summary.grade).toBe("string");
      expect(Array.isArray(data.vulnerabilities)).toBe(true);
      const row = await scanRow(id);
      expect(row?.status).toBe("complete");
      expect(row?.credentialsEncrypted).toBeNull();
    }, 240_000);

    it("runs the scanner's own TLS check and does not call SSL Labs by default", async () => {
      // Qualys's terms need their permission for commercial use, so SSL Labs is opt-in. The ledger saved with
      // the report says which checks the job actually ran.
      const id = await queuedScan();
      await work.processScanJob(jobFor(id));
      const names = (((await reportsOf(id))[0]!.data as any).tests as Array<{ name: string }>).map((t) => t.name.toLowerCase());
      expect(names.some((n) => n.includes("tls"))).toBe(true);
      expect(names.some((n) => n.includes("ssl labs"))).toBe(false);
    }, 240_000);
  });
});

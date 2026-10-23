/**
 * GET /reports/:id against a REAL Postgres (BILLING_TEST_DATABASE_URL).
 *
 * The route validates the stored report against a strict schema that does not list
 * `tests` or `compliance`. Those must still reach the owner: without the test ledger
 * the report says "not recorded" and the OWASP card says "no record" for every
 * category, on a scan that recorded all of it. The comparison with the previous scan
 * is the real lib/scanDiffLoader reading real rows.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import pino from "pino";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const tests = [{ group: "passive", name: "JWT analysis", status: "ran", findings: 0, durationMs: 3 }];
const compliance = { frameworks: [], disclaimer: "Not a compliance verdict." };
const summary = { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, riskScore: 0, grade: "A", executiveSummary: "ok" };
const vuln = { name: "Missing Content-Security-Policy (CSP)", severity: "high", category: "HTTP Security", evidence: "" };
const headersRan = { group: "passive", name: "response headers and cookies", status: "ran", findings: 0, durationMs: 2 };
const stored = (vulnerabilities: unknown[], ledger: unknown[] = tests) => ({ vulnerabilities, summary, technologies: [], targetUrl: "https://example.com", tests: ledger, compliance });

suite("GET /reports/:id (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let server: Server;
  let base: string;
  let userId: string;
  let otherId: string;
  let signedIn: { id: string } | null;
  const scanIds: string[] = [];
  let site = 0;

  /** A finished scan and its report for `targetUrl`, `daysAgo` days old. */
  async function report(owner: string, targetUrl: string, daysAgo: number, data: unknown) {
    const { db, scansTable, reportsTable } = dbMod;
    const at = new Date(Date.now() - daysAgo * 86_400_000);
    const [scan] = await db
      .insert(scansTable)
      .values({ userId: owner, userEmail: `reports-${Date.now()}-${scanIds.length}@example.com`, targetUrl, tier: "deep", status: "complete" })
      .returning({ id: scansTable.id });
    scanIds.push(scan!.id);
    const [r] = await db
      .insert(reportsTable)
      .values({ scanId: scan!.id, userId: owner, targetUrl, tier: "deep", scannedAt: at, duration: 10, data: data as never })
      .returning({ id: reportsTable.id });
    return r!.id;
  }
  const get = async (id: string) => {
    const res = await fetch(`${base}/${id}`);
    return { status: res.status, body: (await res.json()) as any };
  };
  const newSite = () => `https://reports-${Date.now()}-${++site}.example/`;

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    const make = async (tag: string) => {
      const [u] = await dbMod.db
        .insert(dbMod.usersTable)
        .values({ email: `${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com` })
        .returning({ id: dbMod.usersTable.id });
      return u!.id;
    };
    userId = await make("reports-owner");
    otherId = await make("reports-other");
    const { default: router } = await import("./reports");
    const app = express();
    app.use((req, _res, next) => {
      Object.assign(req, { isAuthenticated: () => signedIn !== null, user: signedIn, log: pino({ level: "silent" }) });
      next();
    });
    app.use("/api", router);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/reports`;
  }, 60_000);

  afterAll(async () => {
    server?.close();
    const { inArray, eq } = await import("drizzle-orm");
    const { db, scansTable, reportsTable, usersTable } = dbMod;
    if (scanIds.length) {
      await db.delete(reportsTable).where(inArray(reportsTable.scanId, scanIds));
      await db.delete(scansTable).where(inArray(scansTable.id, scanIds));
    }
    for (const id of [userId, otherId]) if (id) await db.delete(usersTable).where(eq(usersTable.id, id));
    await dbMod?.pool?.end?.();
  });

  it("attaches what changed since the last scan, when there is a previous one", async () => {
    signedIn = { id: userId };
    const url = newSite();
    // A finding counts as fixed only when the check that finds it ran again.
    await report(userId, url, 3, stored([vuln], [headersRan]));
    const id = await report(userId, url, 0, stored([], [headersRan]));
    const { status, body } = await get(id);
    expect(status).toBe(200);
    expect(body.data.changes.fixed.map((f: { name: string }) => f.name)).toEqual([vuln.name]);
    expect(body.data.tests).toEqual([headersRan]);
  });

  it("leaves changes out for a first scan", async () => {
    signedIn = { id: userId };
    const id = await report(userId, newSite(), 0, stored([]));
    expect((await get(id)).body.data.changes).toBeUndefined();
  });

  it("returns the stored test ledger and compliance mapping to the owner", async () => {
    signedIn = { id: userId };
    const id = await report(userId, newSite(), 0, stored([]));
    const { body } = await get(id);
    expect(body.data.tests).toEqual(tests);
    expect(body.data.compliance).toEqual(compliance);
    // and still validates the fields it does list
    expect(body.data.summary.grade).toBe("A");
  });

  it("answers 404 to a different user, and 401 when signed out", async () => {
    const id = await report(userId, newSite(), 0, stored([]));
    signedIn = { id: otherId };
    expect((await get(id)).status).toBe(404);
    signedIn = null;
    expect((await get(id)).status).toBe(401);
  });
});

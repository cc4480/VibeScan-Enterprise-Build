/**
 * Share links against a REAL Postgres: the token is stored only as a hash, the public endpoint resolves it,
 * revocation is by id, and the list never returns a token. Skips unless a throwaway database is supplied
 * (see billing.integration.test.ts).
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import express from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("share links (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let server: http.Server;
  let base = "";
  let userId = "";
  let reportId = "";
  let sql: typeof import("drizzle-orm").sql;

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    sql = (await import("drizzle-orm")).sql;
    const { default: sharesRouter } = await import("../routes/shares");
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      (req as unknown as { isAuthenticated: () => boolean }).isAuthenticated = () => true;
      (req as unknown as { user: { id: string } }).user = { id: userId };
      next();
    });
    app.use("/api", sharesRouter);
    await new Promise<void>((resolve) => { server = app.listen(0, "127.0.0.1", () => resolve()); });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
  }, 60_000);
  afterAll(async () => { server?.close(); await dbMod?.pool?.end?.(); });

  beforeEach(async () => {
    const { db, usersTable, reportsTable, scansTable } = dbMod;
    await db.execute(sql`TRUNCATE report_shares, reports, scans CASCADE`);
    const [u] = await db.insert(usersTable).values({ email: `share-${Date.now()}-${Math.random()}@example.com` }).returning({ id: usersTable.id });
    userId = u!.id;
    const [scan] = await db.insert(scansTable).values({ userId, userEmail: "owner@example.com", targetUrl: "https://example.com", tier: "deep", status: "complete" }).returning({ id: scansTable.id });
    const [rep] = await db.insert(reportsTable).values({ scanId: scan!.id, userId, targetUrl: "https://example.com", tier: "deep", scannedAt: new Date(), duration: 1, data: { vulnerabilities: [], tests: [] } as never }).returning({ id: reportsTable.id });
    reportId = rep!.id;
  });

  const create = async () => (await fetch(`${base}/reports/${reportId}/shares`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).json() as Promise<{ id: string; token: string }>;

  it("stores only a hash, and the public endpoint resolves the token", async () => {
    const share = await create();
    expect(share.token).toMatch(/^[0-9a-f]{64}$/);

    const { db, reportSharesTable } = dbMod;
    const rows = await db.select().from(reportSharesTable);
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows[0])).not.toContain(share.token);
    expect(rows[0]!.tokenHash).toMatch(/^[0-9a-f]{64}$/);

    const ok = await fetch(`${base}/share/${share.token}`);
    expect(ok.status).toBe(200);
    expect((await fetch(`${base}/share/${"0".repeat(64)}`)).status).toBe(404);
    // The hash is not a credential: presenting it does not open the link.
    expect((await fetch(`${base}/share/${rows[0]!.tokenHash}`)).status).toBe(404);
  });

  it("lists links without their token, and revokes by id", async () => {
    const share = await create();
    const list = (await (await fetch(`${base}/reports/${reportId}/shares`)).json()) as Array<Record<string, unknown>>;
    expect(list).toHaveLength(1);
    expect(list[0]).not.toHaveProperty("token");
    expect(list[0]!["id"]).toBe(share.id);

    expect((await fetch(`${base}/reports/${reportId}/shares/${share.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await fetch(`${base}/share/${share.token}`)).status).toBe(404);
    expect((await fetch(`${base}/reports/${reportId}/shares/${share.id}`, { method: "DELETE" })).status).toBe(404);
    expect((await fetch(`${base}/reports/${reportId}/shares/not-a-uuid`, { method: "DELETE" })).status).toBe(404);
  });
});

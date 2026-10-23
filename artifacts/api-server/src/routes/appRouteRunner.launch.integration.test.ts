/**
 * launchScan runs the website's real scan-launch handler, against a REAL Postgres
 * (BILLING_TEST_DATABASE_URL): the real limiters, free-trial charge, SSRF guard and job queue.
 * The proof is the scan row it leaves behind.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Request } from "express";
import { dbSuiteOf, useRealDb, openDb, uniqueEmail } from "../lib/realDb.testkit";

useRealDb();
// Each accepted scan spends one free-trial scan; the default allowance is three.
if (process.env["BILLING_TEST_DATABASE_URL"]) process.env["FREE_TRIAL_SCAN_LIMIT"] = "50";

dbSuiteOf(describe)("launchScan (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let launchScan: typeof import("./appRouteRunner").launchScan;
  let user: { id: string; email: string };
  const run = Date.now();
  // A loopback target: ALLOW_PRIVATE_SCAN_TARGETS is on in the test config, so the real guard accepts it and no DNS is needed.
  const target = (name: string) => `http://127.0.0.1:9/${name}-${run}`;
  // The real client address, so the per-network limit counts against a bucket of its own.
  const httpReq = { headers: {}, ip: "203.0.113.5" } as unknown as Request;

  const scanFor = async (targetUrl: string) => {
    const [row] = await dbMod.db.select().from(dbMod.scansTable).where(eq(dbMod.scansTable.targetUrl, targetUrl));
    return row;
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    ({ launchScan } = await import("./appRouteRunner"));
    const email = uniqueEmail("launch");
    const [u] = await dbMod.db.insert(dbMod.usersTable).values({ email }).returning({ id: dbMod.usersTable.id });
    user = { id: u!.id, email };
  }, 60_000);

  afterAll(async () => {
    await dbMod.db.delete(dbMod.scansTable).where(eq(dbMod.scansTable.userId, user.id));
    await dbMod.db.delete(dbMod.usersTable).where(eq(dbMod.usersTable.id, user.id));
    await dbMod?.pool?.end?.();
  });

  it("stores the GitHub repository on the scan when one is given", async () => {
    const url = target("with-repo");
    const out = await launchScan(httpReq, user as never, url, "https://github.com/acme/shop");
    expect(out.status).toBe(201);
    expect(out.body.paidWith).toBe("free");
    expect((await scanFor(url))?.githubRepoUrl).toBe("https://github.com/acme/shop");
  });

  it("stores no repository when there is none", async () => {
    const url = target("no-repo");
    const out = await launchScan(httpReq, user as never, url);
    expect(out.status).toBe(201);
    const row = await scanFor(url);
    expect(row).toBeDefined();
    expect(row?.githubRepoUrl ?? null).toBeNull();
  });

  it("refuses a repository address that is not one, and leaves no scan behind", async () => {
    const url = target("bad-repo");
    const out = await launchScan(httpReq, user as never, url, "not a repository");
    expect(out.status).toBe(400);
    expect(await scanFor(url)).toBeUndefined();
  });
});

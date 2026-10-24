/**
 * Report branding over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): the real routes and tables, and the
 * brand reaching the three places that carry it (the owner's report, a teammate's view of it, and the public shared report).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "../lib/realDb.testkit";

useRealDb();

describe("cleanBrandName", () => {
  it("accepts a business name, trims and collapses it, and reads empty as no brand", async () => {
    const { cleanBrandName } = await import("../lib/branding");
    expect(cleanBrandName("  Acme   Security \u0000 Ltd ")).toBe("Acme Security Ltd");
    expect(cleanBrandName("")).toBeNull();
    expect(cleanBrandName("   ")).toBeNull();
    expect(cleanBrandName(null)).toBeNull();
    expect(cleanBrandName("Müller & Söhne GmbH")).toBe("Müller & Söhne GmbH");
  });
  it.each(["https://evil.example/login", "www.evil.com", "pay@evil.com", "acme.com", "<b>Acme</b>", "x".repeat(61), 42])("refuses %s", async (v) => {
    const { cleanBrandName } = await import("../lib/branding");
    expect(cleanBrandName(v)).toBe(false);
  });
});

dbSuiteOf(describe)("report branding (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let app: TestApp;
  let shares: TestApp;
  let reportsApp: TestApp;
  const users: string[] = [];
  const reports: string[] = [];
  let owner: { id: string };
  let mate: { id: string };
  let reportId: string;
  let shareToken: string;

  type Answer = { status: number; json(): Promise<any> }; // eslint-disable-line @typescript-eslint/no-explicit-any
  const call = (base: string, path: string, init: { method?: string; body?: unknown } = {}): Promise<Answer> =>
    fetch(`${base}${path}`, { method: init.method ?? "GET", headers: { "content-type": "application/json" }, ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}) });

  beforeAll(async () => {
    dbMod = await openDb();
    app = startApp((await import("./branding")).default);
    shares = startApp((await import("./shares")).default);
    reportsApp = startApp((await import("./reports")).default);
    owner = { id: await makeUser(dbMod, "brand-owner") };
    mate = { id: await makeUser(dbMod, "brand-mate") };
    users.push(owner.id, mate.id);
    const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId: owner.id, userEmail: "x@example.com", targetUrl: "https://brand.example.com/", tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
    const data = { summary: { totalVulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, riskScore: 0, grade: "A", executiveSummary: "Fine." }, technologies: [], targetUrl: "https://brand.example.com/", vulnerabilities: [], tests: [] };
    const [r] = await dbMod.db.insert(dbMod.reportsTable).values({ scanId: scan!.id, userId: owner.id, targetUrl: "https://brand.example.com/", tier: "deep", duration: 1, data: data as never }).returning({ id: dbMod.reportsTable.id });
    reportId = r!.id;
    reports.push(reportId);
    const { createReportShare } = await import("../lib/reportShare");
    shareToken = (await createReportShare(reportId, owner.id, "7d")).token;
  }, 60_000);

  afterAll(async () => {
    app.server.close(); shares.server.close(); reportsApp.server.close();
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.reportSharesTable).where(inArray(dbMod.reportSharesTable.reportId, reports));
    await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.id, reports));
    await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
  });

  it("needs a signed-in account", async () => {
    app.as(null);
    expect((await call(app.base, "/account/branding")).status).toBe(401);
    expect((await call(app.base, "/account/branding", { method: "PUT", body: { name: "Acme", poweredBy: true } })).status).toBe(401);
  });

  it("starts with no brand, then saves, reads back and clears it", async () => {
    app.as(owner);
    expect((await (await call(app.base, "/account/branding")).json()).brand).toBeNull();
    const saved = await call(app.base, "/account/branding", { method: "PUT", body: { name: "  Acme   Security ", poweredBy: false } });
    expect(await saved.json()).toEqual({ brand: { name: "Acme Security", poweredBy: false } });
    expect((await (await call(app.base, "/account/branding")).json()).brand).toEqual({ name: "Acme Security", poweredBy: false });
    // Another account is untouched.
    app.as(mate);
    expect((await (await call(app.base, "/account/branding")).json()).brand).toBeNull();
    app.as(owner);
    await call(app.base, "/account/branding", { method: "PUT", body: { name: "", poweredBy: true } });
    expect((await (await call(app.base, "/account/branding")).json()).brand).toBeNull();
  });

  it("refuses a name that is a link, an address, markup, or too long, and keeps what was saved", async () => {
    app.as(owner);
    await call(app.base, "/account/branding", { method: "PUT", body: { name: "Acme", poweredBy: true } });
    for (const name of ["https://evil.example", "a@b.co", "<script>", "x".repeat(61)]) {
      const res = await call(app.base, "/account/branding", { method: "PUT", body: { name, poweredBy: true } });
      expect(res.status, name).toBe(400);
      expect((await res.json()).code).toBe("bad_brand");
    }
    expect((await call(app.base, "/account/branding", { method: "PUT", body: { name: "Acme" } })).status).toBe(400);
    expect((await (await call(app.base, "/account/branding")).json()).brand).toEqual({ name: "Acme", poweredBy: true });
  });

  it("is carried by the public shared report, and by the owner's report", async () => {
    app.as(owner);
    await call(app.base, "/account/branding", { method: "PUT", body: { name: "Acme Security", poweredBy: false } });
    const shared = await (await call(shares.base, `/share/${shareToken}`)).json();
    expect(shared.brand).toEqual({ name: "Acme Security", poweredBy: false });
    reportsApp.as(owner);
    expect((await (await call(reportsApp.base, `/reports/${reportId}`)).json()).brand).toEqual({ name: "Acme Security", poweredBy: false });
  });

  it("says nothing when there is no brand, and never leaks the owner's other details", async () => {
    app.as(owner);
    await call(app.base, "/account/branding", { method: "PUT", body: { name: null, poweredBy: true } });
    const shared = await (await call(shares.base, `/share/${shareToken}`)).json();
    expect(shared.brand).toBeNull();
    expect(Object.keys(shared).sort()).toEqual(["brand", "createdAt", "data", "duration", "id", "scanId", "scannedAt", "targetUrl", "tier"]);
  });
});

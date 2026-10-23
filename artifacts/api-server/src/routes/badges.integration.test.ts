/**
 * The public badge endpoint, over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL). It is an image
 * other sites embed, so the headers matter as much as the body: the rest of /api sends
 * Cross-Origin-Resource-Policy: same-origin and no-store, either of which would silently break a badge pasted
 * into a README.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb, startApp, type TestApp } from "../lib/realDb.testkit";

useRealDb();

// A ledger from a scan that ran with the domain verified, and one from a scan that did not.
const ranVerified = [{ group: "active", name: "injection (XSS, SQLi)", status: "ran" }];
const NOT_VERIFIED = "domain not verified for this account (active tests need proof of ownership)";
const ranUnverified = [
  { group: "passive", name: "security headers", status: "ran" },
  { group: "active", name: "injection (XSS, SQLi)", status: "skipped", reason: NOT_VERIFIED },
];

dbSuiteOf(describe)("badges (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let sql: typeof import("drizzle-orm").sql;
  let app: TestApp;
  const owners: string[] = [];
  const scanIds: string[] = [];
  let n = 0;
  const newOwner = () => {
    const id = `badge-${Date.now()}-${++n}`;
    owners.push(id);
    return id;
  };

  /** A finished scan and its report. `verifiedDomain` also records this owner's current proof for the report's domain. */
  async function report(owner: string, data: unknown, opts: { verifiedDomain?: boolean; host?: string } = {}) {
    const host = opts.host ?? `app-${Date.now()}-${++n}.example.com`;
    const targetUrl = `https://${host}/`;
    const [scan] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId: owner, userEmail: `${owner}@example.com`, targetUrl, tier: "deep", status: "complete" })
      .returning({ id: dbMod.scansTable.id });
    scanIds.push(scan!.id);
    const [r] = await dbMod.db
      .insert(dbMod.reportsTable)
      .values({ scanId: scan!.id, userId: owner, targetUrl, tier: "deep", scannedAt: new Date(), duration: 1, data: data as never })
      .returning({ id: dbMod.reportsTable.id });
    if (opts.verifiedDomain !== false) {
      await dbMod.db.insert(dbMod.domainVerificationsTable).values({ userId: owner, domain: host, token: "t", method: "dns", verifiedAt: new Date() });
    }
    return r!.id;
  }
  const verified = (grade = "B", extra: object = {}) => ({ summary: { grade }, tests: ranVerified, ...extra });
  const mint = (id: string) => fetch(`${app.base}/reports/${id}/badge`, { method: "POST" });
  const revoke = (id: string) => fetch(`${app.base}/reports/${id}/badge`, { method: "DELETE" });
  const svg = (file: string) => fetch(`${app.base}/badge/${file}`);
  /** Mints a badge for a verified report through the real endpoint and returns its token. */
  async function badgeFor(owner: string, data: unknown) {
    app.as({ id: owner });
    const id = await report(owner, data);
    const res = await mint(id);
    expect(res.status).toBe(201);
    return { reportId: id, token: ((await res.json()) as { token: string }).token };
  }

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq, sql } = await import("drizzle-orm"));
    const { default: router } = await import("./badges");
    app = startApp(router);
    await dbMod.db.execute(sql`DO $$ BEGIN
      IF to_regclass('public.report_badges') IS NULL AND to_regclass('public.report_badges_offline') IS NOT NULL THEN
        ALTER TABLE report_badges_offline RENAME TO report_badges;
      END IF; END $$`);
  }, 60_000);

  afterAll(async () => {
    app?.server.close();
    const { inArray } = await import("drizzle-orm");
    if (scanIds.length) {
      await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.scanId, scanIds)); // badges cascade
      await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.id, scanIds));
    }
    if (owners.length) await dbMod.db.delete(dbMod.domainVerificationsTable).where(inArray(dbMod.domainVerificationsTable.userId, owners));
    await dbMod?.pool?.end?.();
  });

  describe("GET /badge/:token.svg", () => {
    it("serves the grade and date as an image other sites can embed", async () => {
      const { token } = await badgeFor(newOwner(), verified("B"));
      app.as(null);
      const res = await svg(`${token}.svg`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toMatch(/^image\/svg\+xml/);
      expect(await res.text()).toContain("grade B");
      // Without these a badge would not load on any other site, or would hit the database per view.
      expect(res.headers.get("cross-origin-resource-policy")).toBe("cross-origin");
      expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
      expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    });

    it("never puts the address, a finding or a report id in the image", async () => {
      const { token, reportId } = await badgeFor(
        newOwner(),
        verified("F", { targetUrl: "https://secret.example.com", vulnerabilities: [{ name: "SQL Injection" }] }),
      );
      app.as(null);
      const body = await (await svg(`${token}.svg`)).text();
      expect(body).not.toContain("secret.example.com");
      expect(body).not.toContain("SQL Injection");
      expect(body).not.toContain(reportId);
    });

    it("answers an unknown token, a revoked one and a malformed one identically", async () => {
      // No oracle for which tokens exist.
      const owner = newOwner();
      const { token: revokedToken, reportId } = await badgeFor(owner, verified("A"));
      await revoke(reportId);
      app.as(null);
      const unknown = await svg(`${randomBytes(18).toString("base64url")}.svg`);
      const revokedRes = await svg(`${revokedToken}.svg`);
      const malformed = await svg("not-a-token.svg");
      const noExtension = await svg(revokedToken);

      const bodies: string[] = [];
      for (const r of [unknown, revokedRes, malformed, noExtension]) {
        expect(r.status).toBe(404);
        expect(r.headers.get("content-type")).toMatch(/^image\/svg\+xml/);
        expect(r.headers.get("cross-origin-resource-policy")).toBe("cross-origin");
        const body = await r.text();
        expect(body).toContain("badge not found");
        bodies.push(body);
      }
      expect(new Set(bodies).size).toBe(1);
    });

    it("reads 'not graded' for a scan a challenge page answered", async () => {
      const { token } = await badgeFor(newOwner(), verified("N/A"));
      app.as(null);
      expect(await (await svg(`${token}.svg`)).text()).toContain("not graded");
    });

    it("shows 'not verified' instead of the grade for a scan that skipped the active tests", async () => {
      // A badge minted before badges needed a verified scan keeps loading, but stops vouching.
      const owner = newOwner();
      const reportId = await report(owner, { summary: { grade: "A" }, tests: ranUnverified }, { verifiedDomain: false });
      const token = randomBytes(18).toString("base64url");
      await dbMod.db.insert(dbMod.reportBadgesTable).values({ reportId, userId: owner, token });
      app.as(null);
      const res = await svg(`${token}.svg`);
      const body = await res.text();
      expect(res.status).toBe(200);
      expect(body).toContain("not verified");
      expect(body).not.toContain("grade A");
    });

    it("shows 'not verified' for a report with no test ledger, which cannot show what ran", async () => {
      const owner = newOwner();
      const reportId = await report(owner, { summary: { grade: "A" } }, { verifiedDomain: false });
      const token = randomBytes(18).toString("base64url");
      await dbMod.db.insert(dbMod.reportBadgesTable).values({ reportId, userId: owner, token });
      app.as(null);
      const body = await (await svg(`${token}.svg`)).text();
      expect(body).toContain("not verified");
      expect(body).not.toContain("grade A");
    });

    // The failure is real: the badge table is taken away (a half-migrated deploy) and put straight back.
    it("answers a database failure with a visible placeholder that is not cached", async () => {
      app.as(null);
      const token = randomBytes(18).toString("base64url");
      await dbMod.db.execute(sql`ALTER TABLE report_badges RENAME TO report_badges_offline`);
      try {
        const res = await svg(`${token}.svg`);
        expect(res.status).toBe(500);
        expect(await res.text()).toContain("badge not found");
        // A database blip must not pin a broken badge in every browser for an hour.
        expect(res.headers.get("cache-control")).toBe("no-store");
      } finally {
        await dbMod.db.execute(sql`ALTER TABLE report_badges_offline RENAME TO report_badges`);
      }
    });
  });

  describe("POST and DELETE /reports/:id/badge", () => {
    it("refuses an anonymous caller, and mints nothing", async () => {
      const owner = newOwner();
      const id = await report(owner, verified());
      app.as(null);
      expect((await mint(id)).status).toBe(401);
      expect(await dbMod.db.select().from(dbMod.reportBadgesTable).where(eq(dbMod.reportBadgesTable.reportId, id))).toHaveLength(0);
    });

    it("refuses someone else's report", async () => {
      const id = await report(newOwner(), verified());
      app.as({ id: newOwner() });
      expect((await mint(id)).status).toBe(404);
      expect(await dbMod.db.select().from(dbMod.reportBadgesTable).where(eq(dbMod.reportBadgesTable.reportId, id))).toHaveLength(0);
    });

    it("mints a badge for the owner and returns copy-paste snippets that do not link to a share", async () => {
      const owner = newOwner();
      app.as({ id: owner });
      const id = await report(owner, verified("A"));
      const res = await mint(id);
      expect(res.status).toBe(201);
      const body = (await res.json()) as { token: string; markdown: string; imageUrl: string };
      expect(body.imageUrl).toContain(`/api/badge/${body.token}.svg`);
      expect(body.markdown).not.toContain("/share/");
      expect(await dbMod.db.select().from(dbMod.reportBadgesTable).where(eq(dbMod.reportBadgesTable.reportId, id))).toHaveLength(1);
    });

    it("hands back the same badge when one already exists, instead of minting a second", async () => {
      const owner = newOwner();
      app.as({ id: owner });
      const id = await report(owner, verified("A"));
      const first = (await (await mint(id)).json()) as { token: string };
      const second = (await (await mint(id)).json()) as { token: string };
      expect(second.token).toBe(first.token);
      expect(await dbMod.db.select().from(dbMod.reportBadgesTable).where(eq(dbMod.reportBadgesTable.reportId, id))).toHaveLength(1);
    });

    it("refuses a report whose scan skipped the active tests because the domain was not verified", async () => {
      const owner = newOwner();
      app.as({ id: owner });
      const id = await report(owner, { summary: { grade: "A" }, tests: ranUnverified });
      const res = await mint(id);
      expect(res.status).toBe(409);
      expect(((await res.json()) as { code: string }).code).toBe("badge_needs_verified_scan");
      expect(await dbMod.db.select().from(dbMod.reportBadgesTable).where(eq(dbMod.reportBadgesTable.reportId, id))).toHaveLength(0);
    });

    it("refuses a report with no test ledger", async () => {
      const owner = newOwner();
      app.as({ id: owner });
      const id = await report(owner, { summary: { grade: "A" } });
      expect((await mint(id)).status).toBe(409);
    });

    it("refuses when this account has not verified the report's domain, even if the scan ran every test", async () => {
      // An operator override (ALLOW_UNVERIFIED_ACTIVE_PROBES) can run active tests with no proof of ownership,
      // so the ledger alone is not enough: the domain must be verified by this account.
      const owner = newOwner();
      app.as({ id: owner });
      const id = await report(owner, verified("A"), { verifiedDomain: false });
      expect((await mint(id)).status).toBe(409);
    });

    it("refuses a domain whose verification has lapsed", async () => {
      const owner = newOwner();
      app.as({ id: owner });
      const id = await report(owner, verified("A"));
      await dbMod.db.update(dbMod.domainVerificationsTable).set({ verifiedAt: new Date(Date.now() - 20 * 86_400_000) }).where(eq(dbMod.domainVerificationsTable.userId, owner));
      expect((await mint(id)).status).toBe(409);
    });

    it("revokes the owner's badge, so the image stops vouching", async () => {
      const owner = newOwner();
      const { token, reportId } = await badgeFor(owner, verified("A"));
      expect((await revoke(reportId)).status).toBe(204);
      const [row] = await dbMod.db.select().from(dbMod.reportBadgesTable).where(eq(dbMod.reportBadgesTable.token, token));
      expect(row!.revokedAt).toBeInstanceOf(Date);
      app.as(null);
      expect((await svg(`${token}.svg`)).status).toBe(404);
    });

    it("will not revoke someone else's badge", async () => {
      const { token, reportId } = await badgeFor(newOwner(), verified("A"));
      app.as({ id: newOwner() });
      expect((await revoke(reportId)).status).toBe(404);
      const [row] = await dbMod.db.select().from(dbMod.reportBadgesTable).where(eq(dbMod.reportBadgesTable.token, token));
      expect(row!.revokedAt).toBeNull();
    });
  });
});

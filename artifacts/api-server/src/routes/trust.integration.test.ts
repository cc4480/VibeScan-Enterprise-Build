/**
 * Trust pages, over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): the real routes, the real tables and the
 * real domain-verification rows. A trust page speaks for a domain in public, so most of this is about when it must NOT.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "../lib/realDb.testkit";

useRealDb();

const ran = (name: string) => ({ group: "g", name, status: "ran", findings: 0, durationMs: 1 });
const VERIFIED_TESTS = [ran("a"), ran("b")];
const UNVERIFIED_TESTS = [ran("a"), { group: "active", name: "injection", status: "skipped", findings: 0, durationMs: 0, reason: "domain not verified: active tests need proof" }];

dbSuiteOf(describe)("trust pages (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let app: TestApp;
  const users: string[] = [];
  let alice: { id: string; email: string };
  let bob: { id: string; email: string };
  let n = 0;
  /** Unique per test, so tests never meet each other's rows. */
  const domain = () => `trust${Date.now()}x${++n}.example.com`;

  type Answer = { status: number; json(): Promise<any>; headers: Headers }; // eslint-disable-line @typescript-eslint/no-explicit-any
  const call = (path: string, init: { method?: string; body?: unknown } = {}): Promise<Answer> =>
    fetch(`${app.base}${path}`, {
      method: init.method ?? "GET",
      headers: { "content-type": "application/json" },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });

  async function verifyDomain(userId: string, d: string, verifiedAt: Date = new Date()) {
    await dbMod.db.insert(dbMod.domainVerificationsTable).values({ userId, domain: d, token: "secscan-verify-test", method: "dns", verifiedAt });
  }
  async function report(userId: string, d: string, over: { tests?: unknown[]; grade?: string; scannedAt?: Date } = {}) {
    const targetUrl = `https://${d}/`;
    const [scan] = await dbMod.db.insert(dbMod.scansTable).values({ userId, userEmail: "x@example.com", targetUrl, tier: "deep", status: "complete" }).returning({ id: dbMod.scansTable.id });
    await dbMod.db.insert(dbMod.reportsTable).values({
      scanId: scan!.id, userId, targetUrl, tier: "deep", duration: 1, ...(over.scannedAt ? { scannedAt: over.scannedAt } : {}),
      data: {
        summary: { grade: over.grade ?? "B", riskScore: 20 },
        vulnerabilities: [{ id: "f1", name: "Secret finding name", severity: "high", category: "Headers", description: "d", evidence: "e", solution: "s" }],
        tests: over.tests ?? VERIFIED_TESTS,
      } as never,
    });
  }

  beforeAll(async () => {
    dbMod = await openDb();
    app = startApp((await import("./trust")).default);
    alice = { id: await makeUser(dbMod, "trust-alice"), email: "alice@example.com" };
    bob = { id: await makeUser(dbMod, "trust-bob"), email: "bob@example.com" };
    users.push(alice.id, bob.id);
  }, 60_000);

  beforeEach(() => app.as(null));

  afterAll(async () => {
    app.server.close();
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.trustPagesTable).where(inArray(dbMod.trustPagesTable.userId, users));
    await dbMod.db.delete(dbMod.domainVerificationsTable).where(inArray(dbMod.domainVerificationsTable.userId, users));
    await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.userId, users));
    await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
  });

  describe("the owner's routes", () => {
    it("need a signed-in account", async () => {
      expect((await call("/trust-pages")).status).toBe(401);
      expect((await call("/trust-pages/shop.example.com", { method: "PUT", body: {} })).status).toBe(401);
      expect((await call("/trust-pages/shop.example.com", { method: "DELETE" })).status).toBe(401);
    });

    it("offers the verified domains that have no page, and lists the pages", async () => {
      const a = domain(), b = domain();
      await verifyDomain(alice.id, a);
      await verifyDomain(alice.id, b);
      app.as(alice);
      expect((await (await call("/trust-pages")).json()).available).toEqual(expect.arrayContaining([a, b]));
      expect((await call(`/trust-pages/${a}`, { method: "PUT", body: { displayName: "Acme" } })).status).toBe(200);
      const after = await (await call("/trust-pages")).json();
      expect(after.available).not.toContain(a);
      expect(after.available).toContain(b);
      expect(after.pages.find((p: { domain: string }) => p.domain === a)).toMatchObject({ enabled: true, displayName: "Acme", accent: null });
    });

    it("does not offer a domain whose verification has lapsed", async () => {
      const d = domain();
      await verifyDomain(alice.id, d, new Date(Date.now() - 20 * 86_400_000));
      app.as(alice);
      expect((await (await call("/trust-pages")).json()).available).not.toContain(d);
    });

    it("refuses a domain the account has not verified", async () => {
      app.as(alice);
      const res = await call(`/trust-pages/${domain()}`, { method: "PUT", body: { displayName: "Acme" } });
      expect(res.status).toBe(403);
      expect((await res.json()).code).toBe("not_verified");
    });

    it("refuses a domain whose verification has lapsed", async () => {
      const d = domain();
      await verifyDomain(alice.id, d, new Date(Date.now() - 20 * 86_400_000));
      app.as(alice);
      expect((await call(`/trust-pages/${d}`, { method: "PUT", body: {} })).status).toBe(403);
    });

    it("refuses a domain that is not a domain, and a colour that is not a colour", async () => {
      const d = domain();
      await verifyDomain(alice.id, d);
      app.as(alice);
      for (const bad of ["not a domain", "localhost", "a..b", "-x.example.com"]) {
        expect((await call(`/trust-pages/${encodeURIComponent(bad)}`, { method: "PUT", body: {} })).status, bad).toBe(400);
      }
      const short = await call(`/trust-pages/${d}`, { method: "PUT", body: { accent: "red" } });
      expect(short.status).toBe(400);
      expect((await short.json()).code).toBe("bad_accent");
      // Something far too long to be a colour is refused before it is looked at.
      expect((await call(`/trust-pages/${d}`, { method: "PUT", body: { accent: "red; } body{display:none" } })).status).toBe(400);
    });

    it("lets only one account have a page for a domain", async () => {
      const d = domain();
      await verifyDomain(alice.id, d);
      await verifyDomain(bob.id, d);
      app.as(alice);
      expect((await call(`/trust-pages/${d}`, { method: "PUT", body: { displayName: "Alice Co" } })).status).toBe(200);
      app.as(bob);
      const res = await call(`/trust-pages/${d}`, { method: "PUT", body: { displayName: "Bob Co" } });
      expect(res.status).toBe(409);
      expect((await res.json()).code).toBe("domain_taken");
      // And Bob did not change Alice's page.
      await report(alice.id, d);
      app.as(null);
      expect((await (await call(`/trust/${d}`)).json()).displayName).toBe("Alice Co");
    });

    it("updates a page, and deletes it", async () => {
      const d = domain();
      await verifyDomain(alice.id, d);
      await report(alice.id, d);
      app.as(alice);
      await call(`/trust-pages/${d}`, { method: "PUT", body: { displayName: "First" } });
      await call(`/trust-pages/${d}`, { method: "PUT", body: { displayName: "  Second  ", accent: "#1A73E8" } });
      app.as(null);
      expect(await (await call(`/trust/${d}`)).json()).toMatchObject({ displayName: "Second", accent: "#1a73e8" });
      app.as(alice);
      await call(`/trust-pages/${d}`, { method: "DELETE" });
      app.as(null);
      expect((await call(`/trust/${d}`)).status).toBe(404);
    });

    it("lets only the owner delete a page", async () => {
      const d = domain();
      await verifyDomain(alice.id, d);
      await report(alice.id, d);
      app.as(alice);
      await call(`/trust-pages/${d}`, { method: "PUT", body: {} });
      app.as(bob);
      await call(`/trust-pages/${d}`, { method: "DELETE" });
      app.as(null);
      expect((await call(`/trust/${d}`)).status).toBe(200);
    });
  });

  describe("the public page", () => {
    async function publish(d: string, tests?: unknown[], body: Record<string, unknown> = { displayName: "Acme Ltd", accent: "#336699" }) {
      await verifyDomain(alice.id, d);
      await report(alice.id, d, tests ? { tests } : {});
      app.as(alice);
      expect((await call(`/trust-pages/${d}`, { method: "PUT", body })).status).toBe(200);
      app.as(null);
    }

    it("shows the grade, the date, the counts and the coverage under the owner's name, with no sign-in", async () => {
      const d = domain();
      await publish(d);
      const res = await call(`/trust/${d}`);
      expect(res.status).toBe(200);
      const view = await res.json();
      expect(view).toMatchObject({
        domain: d, displayName: "Acme Ltd", accent: "#336699", grade: "B", stale: false,
        findings: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 }, coverage: { ran: 2, total: 2 },
      });
      expect(typeof view.scannedAt).toBe("string");
    });

    it("never shows what a finding is, only how many", async () => {
      const d = domain();
      await publish(d);
      expect(JSON.stringify(await (await call(`/trust/${d}`)).json())).not.toContain("Secret finding name");
    });

    it("asks not to be indexed, and may be cached briefly when it exists", async () => {
      const d = domain();
      await publish(d);
      const res = await call(`/trust/${d}`);
      expect(res.headers.get("x-robots-tag")).toBe("noindex");
      expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    });

    it("is not available while turned off, and is again when turned back on", async () => {
      const d = domain();
      await publish(d);
      app.as(alice);
      await call(`/trust-pages/${d}`, { method: "PUT", body: { enabled: false, displayName: "Acme Ltd" } });
      app.as(null);
      expect((await call(`/trust/${d}`)).status).toBe(404);
      app.as(alice);
      await call(`/trust-pages/${d}`, { method: "PUT", body: { enabled: true } });
      app.as(null);
      expect((await call(`/trust/${d}`)).status).toBe(200);
    });

    it("gives the same answer for a page that never existed, one that is off, and one that lapsed", async () => {
      const off = domain(), lapsed = domain(), never = domain();
      await publish(off);
      app.as(alice);
      await call(`/trust-pages/${off}`, { method: "PUT", body: { enabled: false } });
      await publish(lapsed);
      await dbMod.db.update(dbMod.domainVerificationsTable).set({ verifiedAt: new Date(Date.now() - 30 * 86_400_000) });
      app.as(null);
      const answers = await Promise.all([off, lapsed, never].map(async (d) => { const r = await call(`/trust/${d}`); return [r.status, await r.json(), r.headers.get("cache-control")]; }));
      expect(answers[0]).toEqual([404, { error: "This trust page is not available." }, "no-store"]);
      expect(answers[1]).toEqual(answers[0]);
      expect(answers[2]).toEqual(answers[0]);
    });

    it("is not available when the only scans of the domain did not run the active tests", async () => {
      const d = domain();
      await publish(d, UNVERIFIED_TESTS);
      expect((await call(`/trust/${d}`)).status).toBe(404);
    });

    it("speaks for the newest scan whose active tests ran, not an older or an unverified one", async () => {
      const d = domain();
      await verifyDomain(alice.id, d);
      await report(alice.id, d, { grade: "F", scannedAt: new Date(Date.now() - 5 * 86_400_000) });
      await report(alice.id, d, { grade: "A", scannedAt: new Date(Date.now() - 2 * 86_400_000) });
      await report(alice.id, d, { grade: "Z", tests: UNVERIFIED_TESTS, scannedAt: new Date(Date.now() - 1 * 86_400_000) });
      app.as(alice);
      await call(`/trust-pages/${d}`, { method: "PUT", body: {} });
      app.as(null);
      expect((await (await call(`/trust/${d}`)).json()).grade).toBe("A");
    });

    it("does not use another account's scan of the domain", async () => {
      const d = domain();
      await verifyDomain(alice.id, d);
      await report(bob.id, d, { grade: "A" }); // Bob scanned it; Alice owns the page.
      app.as(alice);
      await call(`/trust-pages/${d}`, { method: "PUT", body: {} });
      app.as(null);
      expect((await call(`/trust/${d}`)).status).toBe(404);
    });

    it("marks an old scan as out of date rather than current", async () => {
      const d = domain();
      await verifyDomain(alice.id, d);
      await report(alice.id, d, { scannedAt: new Date(Date.now() - 45 * 86_400_000) });
      app.as(alice);
      await call(`/trust-pages/${d}`, { method: "PUT", body: {} });
      app.as(null);
      expect((await (await call(`/trust/${d}`)).json()).stale).toBe(true);
    });

    it("answers a malformed domain like any missing page", async () => {
      for (const bad of ["not a domain", "localhost", "%00", "a..b"]) {
        const res = await call(`/trust/${encodeURIComponent(bad)}`);
        expect(res.status, bad).toBe(404);
      }
    });
  });
});

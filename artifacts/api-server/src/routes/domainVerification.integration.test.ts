/**
 * What the verification endpoints say about expiry, and that a lapsed row can be verified again, against a
 * REAL Postgres (BILLING_TEST_DATABASE_URL). The gate's own date logic is in activeProbeGate.integration.test.ts;
 * this is the client-facing side: `verified` must mean "valid now", not "once passed", or the page would show a
 * green tick for a domain the scanner has already stopped probing.
 *
 * Not covered here: the check PASSING. That needs a public domain publishing the token over valid TLS (or a TXT
 * record), which a test cannot create, so the pass-and-stamp case is left to a live verification.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, startApp, type TestApp } from "../lib/realDb.testkit";

useRealDb();

const DAY = 86_400_000;

dbSuiteOf(describe)("domain verification endpoints (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let app: TestApp;
  const owners: string[] = [];
  let n = 0;
  const owner = () => {
    const id = `dv-${Date.now()}-${++n}`;
    owners.push(id);
    return id;
  };
  /** A verification row whose proof was last seen `ageDays` ago (null: never verified). */
  async function seed(userId: string, domain: string, ageDays: number | null) {
    const verifiedAt = ageDays === null ? null : new Date(Date.now() - ageDays * DAY);
    await dbMod.db.insert(dbMod.domainVerificationsTable).values({
      userId, domain, token: "secscan-verify-abc", method: verifiedAt ? "dns" : null, verifiedAt, lastCheckedAt: verifiedAt,
    });
    return verifiedAt;
  }
  const rowOf = async (userId: string) => (await dbMod.db.select().from(dbMod.domainVerificationsTable).where(eq(dbMod.domainVerificationsTable.userId, userId)))[0]!;
  const list = async () => ((await (await fetch(`${app.base}/domain-verifications`)).json()) as any).verifications as any[];
  const check = (domain: string) => fetch(`${app.base}/domain-verifications/${domain}/check`, { method: "POST" });

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    const { default: router } = await import("./domainVerification");
    app = startApp(router);
  }, 60_000);

  afterAll(async () => {
    app?.server.close();
    const { inArray } = await import("drizzle-orm");
    if (owners.length) await dbMod.db.delete(dbMod.domainVerificationsTable).where(inArray(dbMod.domainVerificationsTable.userId, owners));
    await dbMod?.pool?.end?.();
  });

  describe("GET /domain-verifications", () => {
    it("reports a recent verification as verified, with the date it lapses", async () => {
      const u = owner();
      app.as({ id: u });
      const verifiedAt = (await seed(u, "example.com", 3))!;
      const v = (await list())[0];
      expect(v.verified).toBe(true);
      expect(new Date(v.verifiedAt)).toEqual(verifiedAt);
      expect(new Date(v.expiresAt)).toEqual(new Date(verifiedAt.getTime() + 14 * DAY));
    });

    it("reports a lapsed verification as not verified, still carrying the token to republish", async () => {
      const u = owner();
      app.as({ id: u });
      const verifiedAt = (await seed(u, "example.com", 20))!;
      const v = (await list())[0];
      expect(v.verified).toBe(false);
      expect(new Date(v.expiresAt)).toEqual(new Date(verifiedAt.getTime() + 14 * DAY)); // in the past
      expect(v.token).toBe("secscan-verify-abc");
    });

    it("draws the line at 14 days, the same side the gate's SQL does", async () => {
      // Seeded a moment ago at exactly 14 days, so by the time it is read it is a hair past the window.
      const u = owner();
      app.as({ id: u });
      await seed(u, "example.com", 14);
      expect((await list())[0].verified).toBe(false);
      const u2 = owner();
      app.as({ id: u2 });
      await seed(u2, "example.com", 13.99);
      expect((await list())[0].verified).toBe(true);
    });

    it("reports a never-verified row with no dates", async () => {
      const u = owner();
      app.as({ id: u });
      await seed(u, "example.com", null);
      expect((await list())[0]).toMatchObject({ verified: false, verifiedAt: null, expiresAt: null });
    });

    it("lists only the caller's own rows", async () => {
      const mine = owner();
      await seed(mine, "mine.example.com", 1);
      await seed(owner(), "theirs.example.com", 1);
      app.as({ id: mine });
      expect((await list()).map((v) => v.domain)).toEqual(["mine.example.com"]);
    });
  });

  describe("POST /domain-verifications/:domain/check", () => {
    it("answers a still-valid verification without running another check", async () => {
      const u = owner();
      app.as({ id: u });
      await seed(u, "example.com", 2);
      const before = await rowOf(u);
      const res = await check("example.com");
      expect(res.status).toBe(200);
      expect(((await res.json()) as any).verification.verified).toBe(true);
      expect((await rowOf(u)).lastCheckedAt).toEqual(before.lastCheckedAt); // nothing was re-checked or rewritten
    });

    it("answers 409 for a lapsed row whose proof is still missing, and does not move verifiedAt", async () => {
      // A real check: this host publishes no secscan TXT record and no well-known file.
      const u = owner();
      app.as({ id: u });
      const domain = `no-proof-${Date.now()}.example.com`;
      const verifiedAt = await seed(u, domain, 20);
      const res = await check(domain);
      expect(res.status).toBe(409);
      expect(((await res.json()) as any).verification.verified).toBe(false);
      const after = await rowOf(u);
      expect(after.verifiedAt).toEqual(verifiedAt);
      expect(after.lastCheckedAt!.getTime()).toBeGreaterThan(verifiedAt!.getTime()); // it did look
    }, 30_000);

    it("refuses another user's domain, and a signed-out caller", async () => {
      const theirs = owner();
      await seed(theirs, "example.com", 20);
      app.as({ id: owner() });
      expect((await check("example.com")).status).toBe(404);
      app.as(null);
      expect((await check("example.com")).status).toBe(401);
    });
  });
});

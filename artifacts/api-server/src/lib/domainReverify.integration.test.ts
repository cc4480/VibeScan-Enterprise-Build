/**
 * The re-verification pass, against a REAL Postgres (BILLING_TEST_DATABASE_URL). The proof check is the
 * function the pass is given (`opts.verify`); each test hands it a plain function saying which domains still
 * publish their proof, because how proof is found is not what is under test.
 *
 * What it has to get right: a row whose proof is still there is moved forward, one whose proof is gone is NOT
 * (that is what lets it lapse), one domain blowing up does not take the others down, and the pass stays bounded.
 * The table is emptied before each test, so run it with --no-file-parallelism like the other database suites.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb } from "./realDb.testkit";

useRealDb();

const HOUR = 3_600_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

dbSuiteOf(describe)("reverifyDomains (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let sql: typeof import("drizzle-orm").sql;
  let re: typeof import("./domainReverify");
  let n = 0;

  /** A verified domain not checked for `staleHours` (null: never checked). */
  async function due(domain: string, staleHours: number | null = 48) {
    const verifiedAt = new Date(Date.now() - 5 * 86_400_000);
    await dbMod.db.insert(dbMod.domainVerificationsTable).values({
      userId: `rv-${++n}`, domain, token: `tok-${domain}`, method: "dns", verifiedAt,
      lastCheckedAt: staleHours === null ? null : new Date(Date.now() - staleHours * HOUR),
    });
    return verifiedAt;
  }
  const rowOf = async (domain: string) => {
    const { eq } = await import("drizzle-orm");
    return (await dbMod.db.select().from(dbMod.domainVerificationsTable).where(eq(dbMod.domainVerificationsTable.domain, domain)))[0]!;
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ sql } = await import("drizzle-orm"));
    re = await import("./domainReverify");
    await dbMod.db.execute(sql`DO $$ BEGIN
      IF to_regclass('public.domain_verifications') IS NULL AND to_regclass('public.domain_verifications_offline') IS NOT NULL THEN
        ALTER TABLE domain_verifications_offline RENAME TO domain_verifications;
      END IF; END $$`);
  }, 60_000);

  beforeEach(async () => {
    await dbMod.db.execute(sql`TRUNCATE domain_verifications`);
  });

  afterAll(async () => {
    await dbMod.db.execute(sql`TRUNCATE domain_verifications`);
    await dbMod?.pool?.end?.();
  });

  it("moves verifiedAt forward for a row whose proof is still there, and records how it passed", async () => {
    const before = await due("alive.example.com");
    const now = new Date();
    const r = await re.reverifyDomains({ verify: async () => "well_known", now });
    expect(r).toEqual({ refreshed: 1, failed: 0, errored: 0, capped: false });
    const row = await rowOf("alive.example.com");
    expect(row.verifiedAt).toEqual(now);
    expect(row.verifiedAt!.getTime()).toBeGreaterThan(before.getTime());
    expect(row.lastCheckedAt).toEqual(now);
    expect(row.method).toBe("well_known");
  });

  it("leaves verifiedAt alone for a row whose proof is gone, so it can lapse", async () => {
    const before = await due("gone.example.com");
    const now = new Date();
    const r = await re.reverifyDomains({ verify: async () => null, now });
    expect(r).toEqual({ refreshed: 0, failed: 1, errored: 0, capped: false });
    const row = await rowOf("gone.example.com");
    expect(row.verifiedAt).toEqual(before); // untouched
    expect(row.lastCheckedAt).toEqual(now); // but it was looked at
  });

  it("hands the check each row's own domain and token", async () => {
    await due("a.example.com");
    const seen: string[] = [];
    await re.reverifyDomains({ verify: async (d, t) => { seen.push(`${d}|${t}`); return "dns"; } });
    expect(seen).toEqual(["a.example.com|tok-a.example.com"]);
  });

  it("handles a mixed batch, each row on its own result", async () => {
    await due("yes.example.com");
    await due("no.example.com");
    await due("yes2.example.com");
    const r = await re.reverifyDomains({ verify: async (d) => (d.startsWith("yes") ? "dns" : null) });
    expect(r).toMatchObject({ refreshed: 2, failed: 1, errored: 0 });
  });

  it("isolates a check that throws: the other domains are still processed", async () => {
    await due("boom.example.com");
    await due("fine.example.com");
    const now = new Date();
    const r = await re.reverifyDomains({
      verify: async (d) => { if (d === "boom.example.com") throw new Error("dns blew up"); return "dns"; },
      now,
    });
    expect(r).toMatchObject({ refreshed: 1, errored: 1 });
    expect((await rowOf("fine.example.com")).verifiedAt).toEqual(now);
    expect((await rowOf("boom.example.com")).lastCheckedAt!.getTime()).toBeLessThan(now.getTime()); // the throwing row was not stamped
  });

  it("skips rows checked recently, never-verified rows, and takes never-checked rows first", async () => {
    await due("recent.example.com", 1); // checked an hour ago: not due
    await due("stale.example.com", 48);
    await due("never.example.com", null);
    await dbMod.db.insert(dbMod.domainVerificationsTable).values({ userId: "rv-unverified", domain: "unverified.example.com", token: "t", verifiedAt: null });
    const order: string[] = [];
    await re.reverifyDomains({ verify: async (d) => { order.push(d); return "dns"; }, concurrency: 1 });
    expect(order).toEqual(["never.example.com", "stale.example.com"]);
  });

  it("stops at the per-run cap and says so", async () => {
    for (const d of ["c1", "c2", "c3"]) await due(`${d}.example.com`);
    let calls = 0;
    const r = await re.reverifyDomains({ verify: async () => { calls++; return "dns"; }, maxPerRun: 2 });
    expect(r).toMatchObject({ refreshed: 2, capped: true });
    expect(calls).toBe(2);
  });

  it("is not capped when exactly the cap is due", async () => {
    await due("e1.example.com");
    await due("e2.example.com");
    const r = await re.reverifyDomains({ verify: async () => "dns", maxPerRun: 2 });
    expect(r).toMatchObject({ refreshed: 2, capped: false });
  });

  it("never has more than the concurrency limit of checks in flight, and uses all of it", async () => {
    for (let i = 0; i < 8; i++) await due(`k${i}.example.com`);
    let inFlight = 0;
    let peak = 0;
    await re.reverifyDomains({
      concurrency: 3,
      verify: async () => { inFlight++; peak = Math.max(peak, inFlight); await sleep(60); inFlight--; return "dns"; },
    });
    expect(peak).toBe(3);
  });

  it("defaults to a concurrency of 5", async () => {
    expect(re.REVERIFY_CONCURRENCY).toBe(5);
    for (let i = 0; i < 12; i++) await due(`d${i}.example.com`);
    let inFlight = 0;
    let peak = 0;
    await re.reverifyDomains({ verify: async () => { inFlight++; peak = Math.max(peak, inFlight); await sleep(60); inFlight--; return "dns"; } });
    expect(peak).toBe(5);
  });

  it("gives up on a check that hangs, counting it as errored instead of stalling the pass", async () => {
    await due("hang.example.com");
    await due("ok.example.com");
    const r = await re.reverifyDomains({ verify: (d) => (d === "hang.example.com" ? new Promise(() => {}) : Promise.resolve("dns")) });
    expect(r).toMatchObject({ refreshed: 1, errored: 1 });
  }, 60_000);

  it("uses the real proof check when none is injected: a domain publishing nothing fails it", async () => {
    const domain = `no-proof-${Date.now()}.example.com`;
    await due(domain);
    const r = await re.reverifyDomains();
    expect(r).toMatchObject({ refreshed: 0, failed: 1, errored: 0 });
  }, 40_000);

  it("does nothing, and runs no checks, when no row is due", async () => {
    let calls = 0;
    const r = await re.reverifyDomains({ verify: async () => { calls++; return "dns"; } });
    expect(r).toEqual({ refreshed: 0, failed: 0, errored: 0, capped: false });
    expect(calls).toBe(0);
  });

  it("lets a failure to load the rows propagate, so the job is recorded as failed", async () => {
    await dbMod.db.execute(sql`ALTER TABLE domain_verifications RENAME TO domain_verifications_offline`);
    try {
      await expect(re.reverifyDomains({ verify: async () => "dns" })).rejects.toThrow();
    } finally {
      await dbMod.db.execute(sql`ALTER TABLE domain_verifications_offline RENAME TO domain_verifications`);
    }
  });
});

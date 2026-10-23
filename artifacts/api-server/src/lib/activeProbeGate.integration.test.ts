/**
 * The gate decides whether we are allowed to send attack traffic at somebody. Every case below is a way that
 * decision could go wrong in a direction that matters: attacking an unverified host, or an error being read
 * as consent. It runs against a REAL Postgres (BILLING_TEST_DATABASE_URL), so a query that forgot the userId or
 * the domain predicate returns the wrong row and fails the cross-user and cross-domain cases, and the expiry
 * boundary is the real SQL comparison on real timestamps.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb } from "./realDb.testkit";

useRealDb();

const ENV_KEYS = ["ALLOW_UNVERIFIED_ACTIVE_PROBES", "DEV_SKIP_DOMAIN_VERIFICATION", "NODE_ENV"] as const;
const DAY = 86_400_000;

dbSuiteOf(describe)("activeProbesUnlocked (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let sql: typeof import("drizzle-orm").sql;
  let gate: typeof import("./activeProbeGate");
  const saved: Record<string, string | undefined> = {};
  const owners: string[] = [];
  let n = 0;
  /** A fresh owner id per test: verifications are keyed by user and domain, and the table is shared. */
  const owner = () => {
    const id = `gate-${Date.now()}-${++n}`;
    owners.push(id);
    return id;
  };

  /** A verification row whose proof was last seen `ageDays` ago (null: never verified). */
  async function seed(userId: string, domain: string, ageDays: number | null = 0) {
    await dbMod.db.insert(dbMod.domainVerificationsTable).values({
      userId, domain, token: "t", method: "dns", verifiedAt: ageDays === null ? null : new Date(Date.now() - ageDays * DAY),
    });
  }
  const unlocked = (userId: string, url: string) => gate.activeProbesUnlocked(userId, url);

  beforeAll(async () => {
    dbMod = await openDb();
    ({ sql } = await import("drizzle-orm"));
    gate = await import("./activeProbeGate");
    // Heal a database left half-way through the lookup-failure test below by an interrupted run.
    await dbMod.db.execute(sql`DO $$ BEGIN
      IF to_regclass('public.domain_verifications') IS NULL AND to_regclass('public.domain_verifications_offline') IS NOT NULL THEN
        ALTER TABLE domain_verifications_offline RENAME TO domain_verifications;
      END IF; END $$`);
  }, 60_000);

  beforeEach(() => {
    for (const k of ENV_KEYS) saved[k] = process.env[k];
    for (const k of ENV_KEYS) delete process.env[k];
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    if (owners.length) await dbMod.db.delete(dbMod.domainVerificationsTable).where(inArray(dbMod.domainVerificationsTable.userId, owners));
    await dbMod?.pool?.end?.();
  });

  describe("who is unlocked", () => {
    it("denies a domain the user has not verified", async () => {
      expect(await unlocked(owner(), "https://example.com/app")).toBe(false);
    });

    it("allows a domain the same user has verified", async () => {
      const u = owner();
      await seed(u, "myapp.example.com");
      expect(await unlocked(u, "https://myapp.example.com/login")).toBe(true);
    });

    it("fails closed for another user's verification of the same domain", async () => {
      // The row exists and is current, but it belongs to someone else.
      await seed(owner(), "example.com");
      expect(await unlocked(owner(), "https://example.com/app")).toBe(false);
    });

    it("fails closed for the same user's verification of a different domain", async () => {
      const u = owner();
      await seed(u, "other.example.com");
      expect(await unlocked(u, "https://example.com/app")).toBe(false);
    });

    it("denies a target URL it cannot parse", async () => {
      const u = owner();
      await seed(u, "example.com");
      expect(await unlocked(u, "http://")).toBe(false);
    });

    // The failure is real: the table is taken away (a half-migrated deploy), so the lookup genuinely errors, and
    // it is put back straight afterwards. An error must never be read as consent.
    it("denies when the database errors, rather than failing open", async () => {
      const u = owner();
      await seed(u, "example.com");
      expect(await unlocked(u, "https://example.com")).toBe(true);
      await dbMod.db.execute(sql`ALTER TABLE domain_verifications RENAME TO domain_verifications_offline`);
      try {
        expect(await unlocked(u, "https://example.com")).toBe(false);
      } finally {
        await dbMod.db.execute(sql`ALTER TABLE domain_verifications_offline RENAME TO domain_verifications`);
      }
      expect(await unlocked(u, "https://example.com")).toBe(true);
    });
  });

  describe("operator flags", () => {
    it("unlocks everything when the operator flag is set, with no verification at all", async () => {
      process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "true";
      expect(await unlocked(owner(), "https://anything.example.com/")).toBe(true);
    });

    it("honours the dev flag outside production", async () => {
      process.env.DEV_SKIP_DOMAIN_VERIFICATION = "true";
      process.env.NODE_ENV = "development";
      expect(await unlocked(owner(), "https://anything.example.com/")).toBe(true);
    });

    it("ignores the dev flag in production", async () => {
      process.env.DEV_SKIP_DOMAIN_VERIFICATION = "true";
      process.env.NODE_ENV = "production";
      expect(await unlocked(owner(), "https://anything.example.com/")).toBe(false);
    });

    it("treats any value other than the literal 'true' as off", async () => {
      process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "1";
      expect(await unlocked(owner(), "https://anything.example.com/")).toBe(false);
    });
  });

  /** A verification expires VERIFICATION_VALID_DAYS after the proof was last seen, compared in SQL on real timestamps. */
  describe("verification expiry", () => {
    it("keeps the validity window at 14 days", async () => {
      const { VERIFICATION_VALID_DAYS } = await import("./domainVerify");
      expect(VERIFICATION_VALID_DAYS).toBe(14);
    });

    it("allows a proof seen yesterday and one seen 13 days ago", async () => {
      const a = owner();
      const b = owner();
      await seed(a, "example.com", 1);
      await seed(b, "example.com", 13);
      expect(await unlocked(a, "https://example.com/app")).toBe(true);
      expect(await unlocked(b, "https://example.com/app")).toBe(true);
    });

    it("denies a row whose proof is older than the window", async () => {
      const u = owner();
      await seed(u, "example.com", 15);
      expect(await unlocked(u, "https://example.com")).toBe(false);
    });

    it("lets a row age out as time passes, and renews it when the proof is seen again", async () => {
      const u = owner();
      await seed(u, "example.com", 13);
      expect(await unlocked(u, "https://example.com")).toBe(true);
      const { eq } = await import("drizzle-orm");
      const ageTo = (days: number) =>
        dbMod.db.update(dbMod.domainVerificationsTable).set({ verifiedAt: new Date(Date.now() - days * DAY) }).where(eq(dbMod.domainVerificationsTable.userId, u));
      await ageTo(14.5);
      expect(await unlocked(u, "https://example.com")).toBe(false);
      await ageTo(0);
      expect(await unlocked(u, "https://example.com")).toBe(true);
    });

    it("denies a row that was never verified", async () => {
      const u = owner();
      await seed(u, "example.com", null);
      expect(await unlocked(u, "https://example.com")).toBe(false);
    });

    it("applies no expiry when the operator has unlocked the instance", async () => {
      const u = owner();
      await seed(u, "example.com", 400);
      process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "true";
      expect(await unlocked(u, "https://example.com")).toBe(true);
    });
  });
});

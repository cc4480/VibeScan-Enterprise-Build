/**
 * The report-ready email links through a share token so it resolves WITHOUT a session. These pin the
 * properties that make that safe and make it work, against a REAL Postgres (BILLING_TEST_DATABASE_URL).
 *
 * The bug this closes: the email linked at /report/:id, which requires being signed in as the report's
 * owner. Opened on a phone (logged out, or signed into a different account) it rendered a bare
 * "Failed to load report", so the person the report was mailed to could not read it.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, makeUser, uniqueEmail } from "./realDb.testkit";

useRealDb();

dbSuiteOf(describe)("report shares (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let mod: typeof import("./reportShare");
  let eq: typeof import("drizzle-orm").eq;
  let userId: string;
  let reportId: string;
  let scanId: string;

  const stored = async (shareId: string) => {
    const [row] = await dbMod.db.select().from(dbMod.reportSharesTable).where(eq(dbMod.reportSharesTable.id, shareId));
    return row!;
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    mod = await import("./reportShare");
    userId = await makeUser(dbMod, "share-owner");
    const [scan] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId, userEmail: uniqueEmail("share"), targetUrl: "https://share.example/", tier: "deep", status: "complete" })
      .returning({ id: dbMod.scansTable.id });
    scanId = scan!.id;
    const [report] = await dbMod.db
      .insert(dbMod.reportsTable)
      .values({ scanId, userId, targetUrl: "https://share.example/", tier: "deep", scannedAt: new Date(), duration: 1, data: {} as never })
      .returning({ id: dbMod.reportsTable.id });
    reportId = report!.id;
  }, 60_000);

  afterAll(async () => {
    await dbMod.db.delete(dbMod.reportsTable).where(eq(dbMod.reportsTable.id, reportId)); // shares cascade
    await dbMod.db.delete(dbMod.scansTable).where(eq(dbMod.scansTable.id, scanId));
    await dbMod.db.delete(dbMod.usersTable).where(eq(dbMod.usersTable.id, userId));
    await dbMod?.pool?.end?.();
  });

  describe("createReportShare", () => {
    it("scopes the share to the report AND the owner it was passed", async () => {
      const share = await mod.createReportShare(reportId, userId);
      expect(await stored(share.id)).toMatchObject({ reportId, userId });
    });

    // The token is the only thing standing between a URL and one report's contents, so it must be
    // unguessable: 32 bytes of CSPRNG as 64 hex chars.
    it("mints a 64-hex-character token", async () => {
      const share = await mod.createReportShare(reportId, userId);
      expect(share.token).toMatch(/^[0-9a-f]{64}$/);
    });

    it("stores a SHA-256 of the token and never the token itself", async () => {
      const share = await mod.createReportShare(reportId, userId);
      const row = await stored(share.id);
      expect(row.tokenHash).toBe(mod.hashShareToken(share.token));
      expect(row.tokenHash).toMatch(/^[0-9a-f]{64}$/);
      expect(row.tokenHash).not.toBe(share.token);
      expect(JSON.stringify(row)).not.toContain(share.token);
      expect(row).not.toHaveProperty("token");
    });

    it("never repeats a token across calls", async () => {
      const tokens = new Set<string>();
      for (let i = 0; i < 50; i++) tokens.add((await mod.createReportShare(reportId, userId)).token);
      expect(tokens.size).toBe(50);
    });

    it("defaults to no expiry so an emailed report link does not rot", async () => {
      const share = await mod.createReportShare(reportId, userId);
      expect(share.expiresAt).toBeNull();
      expect((await stored(share.id)).expiresAt).toBeNull();
    });

    it("honours an explicit expiry window", async () => {
      const share = await mod.createReportShare(reportId, userId, "7d");
      const at = (await stored(share.id)).expiresAt;
      expect(at).toBeInstanceOf(Date);
      const days = (at!.getTime() - Date.now()) / 86_400_000;
      expect(days).toBeGreaterThan(6.9);
      expect(days).toBeLessThan(7.1);
    });

    it("refuses a share for a report that does not exist", async () => {
      await expect(mod.createReportShare("00000000-0000-4000-8000-000000000000", userId)).rejects.toThrow();
    });
  });

  describe("hashShareToken", () => {
    it("hashes the way the migration backfill does (sha256 of the UTF-8 text, hex)", () => {
      // sha256("abc"): the same value as encode(sha256(convert_to('abc','UTF8')),'hex') in 0026_share_token_hash.sql.
      expect(mod.hashShareToken("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    });
  });

  describe("computeShareExpiry", () => {
    it("returns null for never, a date for the bounded windows", () => {
      expect(mod.computeShareExpiry("never")).toBeNull();
      expect(mod.computeShareExpiry("7d")).toBeInstanceOf(Date);
      expect(mod.computeShareExpiry("30d")).toBeInstanceOf(Date);
    });
  });

  describe("shareUrl", () => {
    // Must be /share/:token: the route App.tsx actually serves. /s/:token serves nothing, and
    // /report/:id is the session-gated path whose 401/404 is the whole bug being fixed.
    it("builds the public /share/ path, not /s/ and not the gated /report/", () => {
      expect(mod.shareUrl("https://secscan.us", "abc123")).toBe("https://secscan.us/share/abc123");
      expect(mod.shareUrl("https://secscan.us", "abc123")).not.toContain("/report/");
    });

    it("does not double the slash when the origin has a trailing one", () => {
      expect(mod.shareUrl("https://secscan.us/", "abc123")).toBe("https://secscan.us/share/abc123");
    });
  });
});

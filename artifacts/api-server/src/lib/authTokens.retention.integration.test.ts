/**
 * Retention of one-time auth rows, against a REAL Postgres.
 *
 * purgeStaleTokens() is the daily housekeeping pass for auth_tokens,
 * pending_logins, pending_registrations, oauth_codes and oauth_refresh_tokens.
 * Each table is judged by its own expiry column. Each row below is labelled by
 * the case it stands for, and the test asserts which labels survive.
 *
 * Skips unless a throwaway database is supplied (see billing.testkit.ts):
 *   BILLING_TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:5432/billing_data
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const DAY = 24 * 60 * 60 * 1000;

suite("purgeStaleTokens retention (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let purge: typeof import("./authTokens").purgeStaleTokens;
  let drizzle: typeof import("drizzle-orm");

  // One owner per run, so the assertions see only this test's rows.
  const user = `ret-${randomUUID()}`;
  const email = `${user}@example.test`;

  // Each case is a row with a particular expiry and use state.
  const now = Date.now();
  const cases = {
    unexpired: { expiresAt: new Date(now + DAY) },
    expiredYesterday: { expiresAt: new Date(now - DAY) },
    expiredLongAgo: { expiresAt: new Date(now - 30 * DAY) },
    usedJustNow: { expiresAt: new Date(now + DAY), usedAt: new Date(now) },
    usedLongAgo: { expiresAt: new Date(now + DAY), usedAt: new Date(now - 30 * DAY) },
    revokedLongAgo: { expiresAt: new Date(now + DAY), revokedAt: new Date(now - 30 * DAY) },
  } as const;
  type Key = keyof typeof cases;

  // The key is carried inside the unique hash/challenge column, so a surviving row can be named.
  const tag = (key: Key) => `${key}.${randomUUID()}`;
  const keyOf = (value: string) => value.split(".")[0] as Key;

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    ({ purgeStaleTokens: purge } = await import("./authTokens"));
    drizzle = await import("drizzle-orm");

    const { db, authTokensTable, pendingLoginsTable, pendingRegistrationsTable, oauthCodesTable, oauthRefreshTokensTable } = dbMod;

    for (const key of Object.keys(cases) as Key[]) {
      const c = cases[key];
      const expiry = { expiresAt: c.expiresAt, usedAt: "usedAt" in c ? c.usedAt : null };
      // Revocation exists only on refresh tokens, so the revoked case is seeded there alone.
      if (key !== "revokedLongAgo") {
        await db.insert(authTokensTable).values({
          userId: user, tokenHash: tag(key), purpose: "email_verify", ...expiry,
        });
        await db.insert(pendingLoginsTable).values({
          userId: user, challengeHash: tag(key), codeHash: "h", ...expiry,
        });
        await db.insert(pendingRegistrationsTable).values({
          email, passwordHash: "scrypt-placeholder", challengeHash: tag(key), codeHash: "h", ...expiry,
        });
        await db.insert(oauthCodesTable).values({
          codeHash: tag(key), clientId: "test-client", userId: user, redirectUri: "https://example.test/cb",
          codeChallenge: "c", familyId: randomUUID(), ...expiry,
        });
      }
      // Revocation exists only on refresh tokens, so only they get the revoked case.
      await db.insert(oauthRefreshTokensTable).values({
        tokenHash: tag(key), clientId: "test-client", userId: user, familyId: randomUUID(),
        ...expiry, revokedAt: "revokedAt" in c ? c.revokedAt : null,
      });
    }
  }, 60_000);

  afterAll(async () => {
    if (dbMod) {
      const { db, authTokensTable, pendingLoginsTable, pendingRegistrationsTable, oauthCodesTable, oauthRefreshTokensTable } = dbMod;
      const { eq } = drizzle;
      await db.delete(authTokensTable).where(eq(authTokensTable.userId, user));
      await db.delete(pendingLoginsTable).where(eq(pendingLoginsTable.userId, user));
      await db.delete(pendingRegistrationsTable).where(eq(pendingRegistrationsTable.email, email));
      await db.delete(oauthCodesTable).where(eq(oauthCodesTable.userId, user));
      await db.delete(oauthRefreshTokensTable).where(eq(oauthRefreshTokensTable.userId, user));
      await dbMod.pool?.end?.();
    }
  });

  it("removes expired and used rows, keeps unexpired ones, judged by each table's own columns", async () => {
    await purge();

    const { db, authTokensTable, pendingLoginsTable, pendingRegistrationsTable, oauthCodesTable, oauthRefreshTokensTable } = dbMod;
    const { eq } = drizzle;

    const survivors = async (rows: Promise<{ v: string }[]>) => (await rows).map((r) => keyOf(r.v)).sort();

    // 7-day grace for expiry and use: a row that expired yesterday is still kept.
    const grace: Key[] = ["unexpired", "expiredYesterday", "usedJustNow"];
    expect(
      await survivors(db.select({ v: authTokensTable.tokenHash }).from(authTokensTable).where(eq(authTokensTable.userId, user))),
    ).toEqual([...grace].sort());
    expect(
      await survivors(db.select({ v: pendingLoginsTable.challengeHash }).from(pendingLoginsTable).where(eq(pendingLoginsTable.userId, user))),
    ).toEqual([...grace].sort());
    expect(
      await survivors(db.select({ v: oauthCodesTable.codeHash }).from(oauthCodesTable).where(eq(oauthCodesTable.userId, user))),
    ).toEqual([...grace].sort());
    expect(
      await survivors(db.select({ v: oauthRefreshTokensTable.tokenHash }).from(oauthRefreshTokensTable).where(eq(oauthRefreshTokensTable.userId, user))),
    ).toEqual([...grace].sort());

    // No grace on expiry: the row holds a scrypt hash of a password not yet set.
    expect(
      await survivors(db.select({ v: pendingRegistrationsTable.challengeHash }).from(pendingRegistrationsTable).where(eq(pendingRegistrationsTable.email, email))),
    ).toEqual(["unexpired", "usedJustNow"].sort());
  });

  it("is idempotent: a second pass removes nothing further that should be kept", async () => {
    await purge();
    const { db, authTokensTable } = dbMod;
    const rows = await db.select({ v: authTokensTable.tokenHash }).from(authTokensTable).where(drizzle.eq(authTokensTable.userId, user));
    expect(rows.map((r) => keyOf(r.v)).sort()).toEqual(["expiredYesterday", "unexpired", "usedJustNow"].sort());
  });
});

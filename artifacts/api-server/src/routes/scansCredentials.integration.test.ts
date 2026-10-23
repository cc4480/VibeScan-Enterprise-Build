/** prepareScanCredentials against a REAL Postgres (BILLING_TEST_DATABASE_URL): the account checks read real user rows. */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { Writable } from "node:stream";
import pino from "pino";
import { dbSuiteOf, useRealDb, openDb, uniqueEmail } from "../lib/realDb.testkit";

useRealDb();

const session = (cookie: string) => ({ mode: "session" as const, authorized: true, cookie });

dbSuiteOf(describe)("prepareScanCredentials (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let prepareScanCredentials: typeof import("./scansCredentials").prepareScanCredentials;
  let decryptCredentials: typeof import("../lib/scanCredentials").decryptCredentials;
  let verifiedId: string;
  let anonymousId: string;
  let unverifiedId: string;
  const logged: string[] = [];
  const log = pino({ level: "info" }, new Writable({ write(chunk, _enc, cb) { logged.push(String(chunk)); cb(); } }));

  const user = async (fields: { passwordHash: string | null; emailVerifiedAt: Date | null }) => {
    const [u] = await dbMod.db.insert(dbMod.usersTable).values({ email: uniqueEmail("creds"), ...fields }).returning({ id: dbMod.usersTable.id });
    return u!.id;
  };

  beforeAll(async () => {
    process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
    dbMod = await openDb();
    ({ prepareScanCredentials } = await import("./scansCredentials"));
    ({ decryptCredentials } = await import("../lib/scanCredentials"));
    verifiedId = await user({ passwordHash: "x", emailVerifiedAt: new Date() });
    anonymousId = await user({ passwordHash: null, emailVerifiedAt: null });
    unverifiedId = await user({ passwordHash: "x", emailVerifiedAt: null });
  }, 60_000);

  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, [verifiedId, anonymousId, unverifiedId]));
    await dbMod?.pool?.end?.();
  });

  it("passes a scan with no logins straight through", async () => {
    const r = await prepareScanCredentials(verifiedId, undefined, undefined, log);
    expect(r).toEqual({ ok: true, credentialsEncrypted: null, secondaryCredentialsEncrypted: null, credentialsAuthorizedAt: null });
  });

  it("refuses logins from an anonymous account (403)", async () => {
    const r = await prepareScanCredentials(anonymousId, session("a=1"), undefined, log);
    expect(r).toMatchObject({ ok: false, status: 403 });
    expect((r as { error: string }).error).toMatch(/needs a registered account/);
  });

  it("refuses logins from an unverified email (403)", async () => {
    const r = await prepareScanCredentials(unverifiedId, session("a=1"), undefined, log);
    expect(r).toEqual({ ok: false, status: 403, error: "Verify your email address before storing login details for a scan." });
  });

  it("refuses logins the scanner could not use (400)", async () => {
    const r = await prepareScanCredentials(verifiedId, { mode: "session", authorized: false, cookie: "a=1" }, undefined, log);
    expect(r).toMatchObject({ ok: false, status: 400 });
    expect((r as { error: string }).error).toMatch(/authorised/);
  });

  it("encrypts the login, stamps when it was authorised, and logs the mode and not the secret", async () => {
    logged.length = 0;
    const r = await prepareScanCredentials(verifiedId, session("sid=secret"), undefined, log);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.credentialsEncrypted).not.toContain("secret");
    expect(decryptCredentials(r.credentialsEncrypted!)).toMatchObject({ cookie: "sid=secret" });
    expect(r.credentialsAuthorizedAt).toBeInstanceOf(Date);
    expect(r.secondaryCredentialsEncrypted).toBeNull();
    expect(logged.length).toBeGreaterThan(0);
    expect(logged.join("")).not.toContain("secret");
  });

  it("encrypts a second, different account", async () => {
    const r = await prepareScanCredentials(verifiedId, session("a=1"), session("b=2"), log);
    expect(r).toMatchObject({ ok: true });
    expect((r as { secondaryCredentialsEncrypted: string }).secondaryCredentialsEncrypted).toBeTruthy();
  });

  it("refuses the same account twice (400)", async () => {
    const r = await prepareScanCredentials(verifiedId, session("a=1"), session("a=1"), log);
    expect(r).toMatchObject({ ok: false, status: 400 });
    expect((r as { error: string }).error).toMatch(/^Second account: this is the same account/);
  });

  it("refuses an unusable second account with the 'Second account' prefix (400)", async () => {
    const r = await prepareScanCredentials(verifiedId, session("a=1"), { mode: "session", authorized: true, cookie: " " }, log);
    expect(r).toMatchObject({ ok: false, status: 400 });
    expect((r as { error: string }).error).toMatch(/^Second account: /);
  });

  it("refuses a second account without a first (400)", async () => {
    const r = await prepareScanCredentials(verifiedId, undefined, session("b=2"), log);
    expect(r).toEqual({ ok: false, status: 400, error: "A second account only works alongside a first one. Add primary credentials too." });
  });
});

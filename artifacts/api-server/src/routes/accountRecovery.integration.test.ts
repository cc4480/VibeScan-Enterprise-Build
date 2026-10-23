/**
 * Password change and reset requests against a REAL Postgres (BILLING_TEST_DATABASE_URL): the real password
 * hashing, session table, API tokens and rate limiter. Nothing here is faked, so "it cuts off every other way
 * in" is shown by the old session and the old API token genuinely stopping working.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import express from "express";
import { dbSuiteOf, useRealDb, openDb, startApp, uniqueEmail, type TestApp } from "../lib/realDb.testkit";

useRealDb();
// A test must never send real mail.
delete process.env["RESEND_API_KEY"];

const OLD = "old-password-123";
const NEW = "brand-new-pass-1";

dbSuiteOf(describe)("account recovery (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let app: TestApp;
  let auth: typeof import("../lib/auth");
  let password: typeof import("../lib/password");
  let apiTokens: typeof import("../lib/apiTokens");
  let shared: typeof import("./accountShared");
  const users: string[] = [];

  /** An account with a real password, a live session on another device and a live API token. */
  async function account() {
    const email = uniqueEmail("recovery");
    const [u] = await dbMod.db
      .insert(dbMod.usersTable)
      .values({ email, passwordHash: await password.hashPassword(OLD), emailVerifiedAt: new Date() })
      .returning({ id: dbMod.usersTable.id });
    const id = u!.id;
    users.push(id);
    const otherDeviceSid = await auth.createSession({ user: { id, email } as never });
    const g = apiTokens.generateToken();
    await dbMod.db.insert(dbMod.apiTokensTable).values({ userId: id, name: "t", tokenHash: g.hash, prefix: g.prefix });
    return { id, email, otherDeviceSid, token: g.token };
  }
  const hashOf = async (id: string) => (await dbMod.db.select({ h: dbMod.usersTable.passwordHash }).from(dbMod.usersTable).where(eq(dbMod.usersTable.id, id)))[0]!.h!;
  const change = (body: unknown) =>
    fetch(`${app.base}/account/password/change`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    auth = await import("../lib/auth");
    password = await import("../lib/password");
    apiTokens = await import("../lib/apiTokens");
    shared = await import("./accountShared");
    const { registerAccountRecovery } = await import("./accountRecovery");
    const router = express.Router();
    registerAccountRecovery(router);
    app = startApp(router);
  }, 60_000);

  beforeEach(() => {
    shared.attempts.clear();
  });

  afterAll(async () => {
    app?.server.close();
    const { inArray } = await import("drizzle-orm");
    if (users.length) {
      await dbMod.db.delete(dbMod.apiTokensTable).where(inArray(dbMod.apiTokensTable.userId, users));
      for (const id of users) await auth.deleteSessionsForUser(id);
      await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
    }
    await dbMod?.pool?.end?.();
  });

  describe("POST /account/password/change: what it cuts off", () => {
    it("stores the new password, revokes API tokens, signs other devices out, and keeps this one signed in", async () => {
      const a = await account();
      expect(await auth.getSession(a.otherDeviceSid)).not.toBeNull();
      expect((await apiTokens.authenticateApiToken(`Bearer ${a.token}`))?.id).toBe(a.id);
      app.as({ id: a.id, email: a.email });

      const res = await change({ currentPassword: OLD, newPassword: NEW });

      expect(res.status).toBe(200);
      expect(await password.verifyPassword(NEW, await hashOf(a.id))).toBe(true);
      expect(await password.verifyPassword(OLD, await hashOf(a.id))).toBe(false);
      expect(await apiTokens.authenticateApiToken(`Bearer ${a.token}`)).toBeNull();
      expect(await auth.getSession(a.otherDeviceSid)).toBeNull();
      // This device gets a fresh session, so the user is not logged out of the page they are standing on.
      const cookie = res.headers.getSetCookie().find((c) => c.startsWith("sid="));
      expect(cookie).toBeDefined();
      const freshSid = cookie!.split(";")[0]!.slice("sid=".length);
      expect(await auth.getSession(freshSid)).not.toBeNull();
    });

    it("revokes nothing when the current password is wrong", async () => {
      const a = await account();
      const before = await hashOf(a.id);
      app.as({ id: a.id, email: a.email });

      const res = await change({ currentPassword: "not-the-password", newPassword: NEW });

      expect(res.status).toBe(401);
      expect(await hashOf(a.id)).toBe(before);
      expect((await apiTokens.authenticateApiToken(`Bearer ${a.token}`))?.id).toBe(a.id);
      expect(await auth.getSession(a.otherDeviceSid)).not.toBeNull();
    });

    it("refuses a signed-out caller, and a new password that is too short", async () => {
      const a = await account();
      app.as(null);
      expect((await change({ currentPassword: OLD, newPassword: NEW })).status).toBe(401);
      app.as({ id: a.id, email: a.email });
      expect((await change({ currentPassword: OLD, newPassword: "short" })).status).toBe(400);
      expect(await password.verifyPassword(OLD, await hashOf(a.id))).toBe(true);
    });
  });

  describe("POST /account/password/forgot: per address", () => {
    // Behind Cloudflare the client address is the one the edge appended, which is how production reads it.
    let savedCf: string | undefined;
    beforeAll(() => { savedCf = process.env["BEHIND_CLOUDFLARE"]; process.env["BEHIND_CLOUDFLARE"] = "true"; });
    afterAll(() => { if (savedCf === undefined) delete process.env["BEHIND_CLOUDFLARE"]; else process.env["BEHIND_CLOUDFLARE"] = savedCf; });

    const forgot = (email: string, ip: string) =>
      fetch(`${app.base}/account/password/forgot`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        body: JSON.stringify({ email }),
      });

    it("refuses the eleventh request for one address, even from a new IP each time", async () => {
      app.as(null);
      const victim = uniqueEmail("victim");
      for (let i = 0; i < 10; i++) expect((await forgot(victim, `198.51.100.${i + 10}`)).status).toBe(200);
      expect((await forgot(victim, "203.0.113.200")).status).toBe(429);
    });

    it("keeps other addresses' allowances separate", async () => {
      app.as(null);
      const victim = uniqueEmail("victim2");
      for (let i = 0; i < 10; i++) await forgot(victim, `198.51.100.${i + 10}`);
      await forgot(victim, "203.0.113.201");
      expect((await forgot(uniqueEmail("someone-else"), "203.0.113.202")).status).toBe(200);
    });
  });
});

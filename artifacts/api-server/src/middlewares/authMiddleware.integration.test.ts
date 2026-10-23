/**
 * Signing in is mandatory, and this is the middleware that decides it, against a REAL Postgres
 * (BILLING_TEST_DATABASE_URL) with real users, real sessions and the real clock.
 *
 * The behaviour being pinned: a bearer UUID the server has never seen is NOT authenticated, and no row is
 * created for it. Until this change any browser could invent a UUID, send it as a bearer token, and be handed a
 * brand-new account with no email and no password, so "log in" was effectively optional and an account was a
 * string in localStorage.
 *
 * Existing anonymous rows still work during the changeover, because their scans, credits and monitors hang off
 * that id and registering promotes the same row in place. That is a deliberate grace window, not an oversight,
 * so it has a test too, along with the switch that closes it.
 *
 * What the usage log SAYS (fields, masking, once a day per user) is tested on the reporter itself in
 * lib/legacyBearer.test.ts. Here the reporter's size shows that a request was or was not logged.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb, uniqueEmail } from "../lib/realDb.testkit";

useRealDb();

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

dbSuiteOf(describe)("authMiddleware (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let authMiddleware: typeof import("./authMiddleware").authMiddleware;
  let reporter: typeof import("../lib/legacyBearer").legacyBearerReporter;
  let auth: typeof import("../lib/auth");
  const ids: string[] = [];
  const sessions: string[] = [];

  /** An anonymous row: the id is the only credential. A promoted account gets an email and/or password. */
  async function row(fields: { email?: string | null; passwordHash?: string | null } = {}) {
    const id = randomUUID();
    ids.push(id);
    await dbMod.db.insert(dbMod.usersTable).values({ id, email: null, ...fields });
    return id;
  }

  /** Runs the middleware on a request-shaped object and reports what it did. */
  async function run(headers: Record<string, string>, cookies: Record<string, string> = {}, extra: { method?: string; path?: string } = {}) {
    const req = { headers, cookies, ...extra } as any;
    let nextCalls = 0;
    await authMiddleware(req, {} as any, () => { nextCalls++; });
    return { req, nextCalls };
  }
  const bearer = (id: string) => ({ authorization: `Bearer ${id}` });
  const clearEnv = () => {
    delete process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"];
    delete process.env["LEGACY_BEARER_SUNSET"];
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    ({ authMiddleware } = await import("./authMiddleware"));
    ({ legacyBearerReporter: reporter } = await import("../lib/legacyBearer"));
    auth = await import("../lib/auth");
  }, 60_000);

  beforeEach(() => {
    reporter.clear();
    clearEnv();
  });

  afterEach(clearEnv);

  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    for (const sid of sessions) await auth.deleteSession(sid);
    if (ids.length) await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, ids));
    await dbMod?.pool?.end?.();
  });

  describe("an unknown bearer UUID", () => {
    // THE change. A self-minted UUID used to mean "make me an account".
    it("is not authenticated and creates no account", async () => {
      const id = randomUUID();
      const { req, nextCalls } = await run(bearer(id));
      expect(req.user).toBeUndefined();
      expect(req.isAuthenticated()).toBe(false);
      expect(nextCalls).toBe(1); // the route decides the status, not the middleware
      expect(await dbMod.db.select().from(dbMod.usersTable).where(eq(dbMod.usersTable.id, id))).toEqual([]);
      expect(reporter.size()).toBe(0);
    });
  });

  describe("an existing anonymous row (the grace window)", () => {
    it("is still authenticated, so nobody loses their scan history mid-changeover", async () => {
      const id = await row();
      const { req } = await run(bearer(id), {}, { method: "GET", path: "/api/scans" });
      expect(req.user?.id).toBe(id);
      expect(req.isAuthenticated()).toBe(true);
    });

    it("is refused once ALLOW_LEGACY_ANONYMOUS_BEARER=false closes the path", async () => {
      const id = await row();
      process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"] = "false";
      expect((await run(bearer(id))).req.user).toBeUndefined();
    });
  });

  describe("the legacy bearer sunset (LEGACY_BEARER_SUNSET)", () => {
    it("still works before the sunset", async () => {
      const id = await row();
      process.env["LEGACY_BEARER_SUNSET"] = "2999-01-01";
      expect((await run(bearer(id))).req.user?.id).toBe(id);
    });

    it("is rejected once the sunset has passed, exactly as if the switch were off, and logs nothing", async () => {
      const id = await row();
      process.env["LEGACY_BEARER_SUNSET"] = "2000-01-01";
      const { req, nextCalls } = await run(bearer(id));
      expect(req.user).toBeUndefined();
      expect(req.isAuthenticated()).toBe(false);
      expect(nextCalls).toBe(1);
      expect(reporter.size()).toBe(0);
    });

    it("flips at the sunset instant: accepted a moment before, rejected after it", async () => {
      const id = await row();
      process.env["LEGACY_BEARER_SUNSET"] = new Date(Date.now() + 2500).toISOString();
      expect((await run(bearer(id))).req.user?.id).toBe(id);
      await sleep(2700);
      expect((await run(bearer(id))).req.user).toBeUndefined();
    });

    it("treats an unparseable sunset as unset, so nobody is locked out by a typo", async () => {
      const id = await row();
      process.env["LEGACY_BEARER_SUNSET"] = "december";
      expect((await run(bearer(id))).req.user?.id).toBe(id);
    });

    it("is overridden by ALLOW_LEGACY_ANONYMOUS_BEARER=false even when the sunset is far off", async () => {
      const id = await row();
      process.env["LEGACY_BEARER_SUNSET"] = "2999-01-01";
      process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"] = "false";
      expect((await run(bearer(id))).req.user).toBeUndefined();
    });

    it("never lets a sunset admit a promoted account", async () => {
      const id = await row({ email: uniqueEmail("promoted"), passwordHash: "argon2id$..." });
      process.env["LEGACY_BEARER_SUNSET"] = "2999-01-01";
      expect((await run(bearer(id))).req.user).toBeUndefined();
      expect(reporter.size()).toBe(0);
    });
  });

  describe("the legacy bearer usage log", () => {
    it("records a request authenticated by the legacy bearer, once per user however many requests they make", async () => {
      const id = await row();
      for (const path of ["/api/scans", "/api/credits", "/api/monitors"]) await run(bearer(id), {}, { method: "GET", path });
      expect(reporter.size()).toBe(1);
    });

    it("records each distinct user", async () => {
      await run(bearer(await row()));
      await run(bearer(await row()));
      expect(reporter.size()).toBe(2);
    });

    it("does not record requests that are not authenticated by the legacy bearer", async () => {
      // Unknown id, promoted account, non-UUID token, a missing header.
      await run(bearer(randomUUID()));
      await run(bearer(await row({ email: uniqueEmail("promoted2"), passwordHash: "x" })));
      await run({ authorization: "Bearer not-a-uuid" });
      await run({});
      expect(reporter.size()).toBe(0);
    });
  });

  describe("a promoted row is never reachable by its old UUID", () => {
    // Registering converts an anonymous row into an account in place, keeping the id. If the UUID kept working it
    // would be a password-equivalent credential that survives every password change and cannot be revoked.
    it("refuses the bearer token once the row has a password", async () => {
      const id = await row({ email: uniqueEmail("pw"), passwordHash: "argon2id$..." });
      expect((await run(bearer(id))).req.user).toBeUndefined();
    });

    // A Google account has no password, so keying on passwordHash alone would leave every Google-only account
    // reachable through its original UUID.
    it("refuses the bearer token for a Google account, which has an email but no password", async () => {
      const id = await row({ email: uniqueEmail("google"), passwordHash: null });
      expect((await run(bearer(id))).req.user).toBeUndefined();
    });
  });

  describe("input that is not a bearer UUID", () => {
    it("ignores a missing or non-Bearer Authorization header", async () => {
      expect((await run({})).req.user).toBeUndefined();
      expect((await run({ authorization: "Basic abc" })).req.user).toBeUndefined();
    });

    it("ignores a token that is not a UUID v4, creating nothing", async () => {
      const before = (await dbMod.db.select().from(dbMod.usersTable)).length;
      const ok = randomUUID();
      for (const bad of ["not-a-uuid", "../../etc/passwd", "' OR 1=1 --", ok.replace("-4", "-5")]) {
        expect((await run(bearer(bad))).req.user).toBeUndefined();
      }
      expect((await dbMod.db.select().from(dbMod.usersTable)).length).toBe(before);
    });
  });

  describe("the session cookie", () => {
    async function session(userId: string) {
      const sid = await auth.createSession({ user: { id: userId, email: "a@b.co" } as never });
      sessions.push(sid);
      return sid;
    }

    it("authenticates from a valid session, even after the legacy sunset", async () => {
      process.env["LEGACY_BEARER_SUNSET"] = "2000-01-01";
      const userId = await row({ email: uniqueEmail("sess") });
      const { req } = await run({}, { sid: await session(userId) });
      expect(req.user?.id).toBe(userId);
    });

    it("takes priority, and never consults the bearer token", async () => {
      const bearerId = await row(); // would authenticate on its own
      const sessionUser = await row({ email: uniqueEmail("sess2") });
      const { req } = await run(bearer(bearerId), { sid: await session(sessionUser) });
      expect(req.user?.id).toBe(sessionUser);
      expect(reporter.size()).toBe(0); // so the legacy bearer was never used
    });

    it("falls through to the bearer path when the session id is not a live session", async () => {
      const id = await row();
      const { req } = await run(bearer(id), { sid: "no-such-session" });
      expect(req.user?.id).toBe(id);
    });
  });
});

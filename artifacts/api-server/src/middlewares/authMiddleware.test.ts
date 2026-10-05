import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Signing in is mandatory, and this is the middleware that decides it.
 *
 * The behaviour being pinned: a bearer UUID the server has never seen is NOT
 * authenticated, and no row is created for it. Until this change any browser
 * could invent a UUID, send it as a bearer token, and be handed a brand-new
 * account with no email and no password — so "log in" was effectively optional
 * and an account was a string in localStorage.
 *
 * Existing anonymous rows still work during the changeover, because their
 * scans, credits and monitors hang off that id and registering promotes the
 * same row in place. That is a deliberate grace window, not an oversight, so it
 * has a test too — along with the switch that closes it.
 */

interface Row {
  id: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  profileImageUrl: string | null;
  passwordHash?: string | null;
}

const users: Row[] = [];
const inserted: unknown[] = [];
const lookups = { count: 0 };

vi.mock("drizzle-orm", () => ({
  eq: (col: string, val: unknown) => ({ col, val }),
}));

vi.mock("@workspace/db", () => ({
  usersTable: { id: "id" },
  db: {
    // If the middleware ever inserts again, this records it and the test that
    // asserts "no account is created" fails.
    insert: () => ({
      values: (v: unknown) => ({
        onConflictDoNothing: () => {
          inserted.push(v);
          return Promise.resolve();
        },
      }),
    }),
    select: () => {
      lookups.count++;
      return {
        from: () => ({
          where: (p: { val: unknown }) => Promise.resolve(users.filter((u) => u.id === p.val)),
        }),
      };
    },
  },
}));

// Captures what the legacy-bearer usage log writes. The real logger is a pino
// instance with a worker-thread transport, which a unit test should not start.
const logged: { warn: Array<[Record<string, unknown>, string]> } = { warn: [] };
vi.mock("../lib/logger", () => ({
  logger: {
    warn: (fields: Record<string, unknown>, msg: string) => logged.warn.push([fields, msg]),
    info: () => undefined,
    error: () => undefined,
  },
}));

const sessionResult: { value: unknown } = { value: null };
vi.mock("../lib/auth", () => ({
  getSession: () => Promise.resolve(sessionResult.value),
}));

const { authMiddleware } = await import("./authMiddleware");
const { legacyBearerReporter } = await import("../lib/legacyBearer");

const ANON_UUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const OTHER_UUID = "9c858901-8a57-4791-81fe-4c455b099bc9";

function run(
  headers: Record<string, string>,
  cookies: Record<string, string> = {},
  extra: { method?: string; path?: string } = {},
) {
  const req = { headers, cookies, ...extra } as any;
  const next = vi.fn();
  return authMiddleware(req, {} as any, next).then(() => ({ req, next }));
}

function clearLegacyEnv() {
  delete process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"];
  delete process.env["LEGACY_BEARER_SUNSET"];
}

beforeEach(() => {
  users.length = 0;
  inserted.length = 0;
  lookups.count = 0;
  logged.warn.length = 0;
  legacyBearerReporter.clear();
  sessionResult.value = null;
  clearLegacyEnv();
});

afterEach(() => {
  vi.useRealTimers();
  clearLegacyEnv();
});

describe("an unknown bearer UUID", () => {
  // THE change. A self-minted UUID used to mean "make me an account".
  it("is not authenticated and creates no account", async () => {
    const { req, next } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user).toBeUndefined();
    expect(req.isAuthenticated()).toBe(false);
    expect(inserted).toEqual([]);
    expect(users).toEqual([]);
    expect(next).toHaveBeenCalled();
  });

  it("still calls next, so the route decides the status rather than the middleware", async () => {
    const { next } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(next).toHaveBeenCalledTimes(1);
  });
});

describe("an existing anonymous row (the grace window)", () => {
  it("is still authenticated, so nobody loses their scan history mid-changeover", async () => {
    users.push({ id: ANON_UUID, email: null, firstName: null, lastName: null, profileImageUrl: null });
    const { req } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user?.id).toBe(ANON_UUID);
  });

  it("is refused once ALLOW_LEGACY_ANONYMOUS_BEARER=false closes the path", async () => {
    users.push({ id: ANON_UUID, email: null, firstName: null, lastName: null, profileImageUrl: null });
    process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"] = "false";
    const { req } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user).toBeUndefined();
  });
});

describe("the legacy bearer sunset (LEGACY_BEARER_SUNSET)", () => {
  function anon() {
    users.push({ id: ANON_UUID, email: null, firstName: null, lastName: null, profileImageUrl: null });
  }

  it("still works before the sunset", async () => {
    anon();
    process.env["LEGACY_BEARER_SUNSET"] = "2999-01-01";
    const { req } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user?.id).toBe(ANON_UUID);
  });

  it("is rejected once the sunset has passed, exactly as if the switch were off", async () => {
    anon();
    process.env["LEGACY_BEARER_SUNSET"] = "2000-01-01";
    const { req, next } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user).toBeUndefined();
    expect(req.isAuthenticated()).toBe(false);
    expect(next).toHaveBeenCalledTimes(1);
    expect(logged.warn).toEqual([]);
  });

  it("flips at the sunset instant: accepted a moment before, rejected at it", async () => {
    anon();
    process.env["LEGACY_BEARER_SUNSET"] = "2026-12-01";
    vi.useFakeTimers({ toFake: ["Date"] });

    vi.setSystemTime(new Date("2026-11-30T23:59:59.000Z"));
    expect((await run({ authorization: `Bearer ${ANON_UUID}` })).req.user?.id).toBe(ANON_UUID);

    vi.setSystemTime(new Date("2026-12-01T00:00:00.000Z"));
    expect((await run({ authorization: `Bearer ${ANON_UUID}` })).req.user).toBeUndefined();
  });

  it("does not consult the database once closed", async () => {
    // Rejected before any lookup, so a closed path costs nothing and reveals nothing.
    process.env["LEGACY_BEARER_SUNSET"] = "2000-01-01";
    const { req } = await run({ authorization: `Bearer ${OTHER_UUID}` });
    expect(req.user).toBeUndefined();
    expect(lookups.count).toBe(0);
    expect(logged.warn).toEqual([]);
  });

  it("treats an unparseable sunset as unset, so nobody is locked out by a typo", async () => {
    anon();
    process.env["LEGACY_BEARER_SUNSET"] = "december";
    const { req } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user?.id).toBe(ANON_UUID);
  });

  it("is overridden by ALLOW_LEGACY_ANONYMOUS_BEARER=false even when the sunset is far off", async () => {
    anon();
    process.env["LEGACY_BEARER_SUNSET"] = "2999-01-01";
    process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"] = "false";
    const { req } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user).toBeUndefined();
  });

  it("never lets a sunset admit a promoted account", async () => {
    users.push({
      id: ANON_UUID, email: "a@b.co", firstName: null, lastName: null,
      profileImageUrl: null, passwordHash: "argon2id$...",
    });
    process.env["LEGACY_BEARER_SUNSET"] = "2999-01-01";
    const { req } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user).toBeUndefined();
    expect(logged.warn).toEqual([]);
  });

  it("does not affect a session cookie after the sunset", async () => {
    process.env["LEGACY_BEARER_SUNSET"] = "2000-01-01";
    sessionResult.value = { user: { id: "real-user", email: "a@b.co" } };
    const { req } = await run({}, { sid: "session-id" });
    expect(req.user?.id).toBe("real-user");
  });
});

describe("the legacy bearer usage log", () => {
  function anon(id = ANON_UUID) {
    users.push({ id, email: null, firstName: null, lastName: null, profileImageUrl: null });
  }

  it("warns with the user id and route when a request is authenticated by the legacy bearer", async () => {
    anon();
    await run({ authorization: `Bearer ${ANON_UUID}` }, {}, { method: "GET", path: "/api/scans" });
    expect(logged.warn).toHaveLength(1);
    const [fields, msg] = logged.warn[0]!;
    expect(fields).toEqual({ event: "legacy_anonymous_bearer", userId: ANON_UUID, route: "GET /api/scans" });
    expect(msg).toMatch(/legacy anonymous bearer/);
  });

  it("logs a given user once, however many requests they make", async () => {
    anon();
    for (const path of ["/api/scans", "/api/credits", "/api/monitors"]) {
      await run({ authorization: `Bearer ${ANON_UUID}` }, {}, { method: "GET", path });
    }
    expect(logged.warn).toHaveLength(1);
  });

  it("logs each distinct user", async () => {
    anon(ANON_UUID);
    anon(OTHER_UUID);
    await run({ authorization: `Bearer ${ANON_UUID}` });
    await run({ authorization: `Bearer ${OTHER_UUID}` });
    expect(logged.warn.map(([f]) => f["userId"])).toEqual([ANON_UUID, OTHER_UUID]);
  });

  it("writes no headers, cookies or query string", async () => {
    anon();
    await run(
      { authorization: `Bearer ${ANON_UUID}`, cookie: "sid=SECRETCOOKIE" },
      {},
      { method: "GET", path: "/api/scans?x=SECRETQUERY" },
    );
    const text = JSON.stringify(logged.warn);
    expect(text).not.toContain("SECRETCOOKIE");
    expect(text).not.toContain("SECRETQUERY");
    expect(text).not.toContain(`Bearer ${ANON_UUID}`);
    expect(Object.keys(logged.warn[0]![0]).sort()).toEqual(["event", "route", "userId"]);
  });

  it("masks a share-link token in the route", async () => {
    anon();
    await run({ authorization: `Bearer ${ANON_UUID}` }, {}, { method: "GET", path: "/api/share/SHARETOKEN123" });
    expect(logged.warn[0]![0]["route"]).toBe("GET /api/share/:token");
  });

  it("does not log requests that are not authenticated by the legacy bearer", async () => {
    // Unknown id, promoted account, session cookie, closed path, non-UUID token.
    await run({ authorization: `Bearer ${ANON_UUID}` });
    users.push({ id: OTHER_UUID, email: "a@b.co", firstName: null, lastName: null, profileImageUrl: null, passwordHash: "x" });
    await run({ authorization: `Bearer ${OTHER_UUID}` });
    sessionResult.value = { user: { id: "real-user", email: "a@b.co" } };
    await run({}, { sid: "session-id" });
    await run({ authorization: "Bearer not-a-uuid" });
    expect(logged.warn).toEqual([]);
  });

  it("never fails the request if the log itself throws", async () => {
    anon();
    const spy = vi.spyOn(legacyBearerReporter, "report").mockImplementation(() => {
      throw new Error("log sink down");
    });
    try {
      const { req, next } = await run({ authorization: `Bearer ${ANON_UUID}` });
      expect(req.user?.id).toBe(ANON_UUID);
      expect(next).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("a promoted row is never reachable by its old UUID", () => {
  // Registering converts an anonymous row into an account in place, keeping the
  // id. If the UUID kept working it would be a password-equivalent credential
  // that survives every password change and cannot be revoked.
  it("refuses the bearer token once the row has a password", async () => {
    users.push({
      id: ANON_UUID, email: "a@b.co", firstName: null, lastName: null,
      profileImageUrl: null, passwordHash: "argon2id$...",
    });
    const { req } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user).toBeUndefined();
  });

  // A Google account has no password, so keying on passwordHash alone would
  // leave every Google-only account reachable through its original UUID.
  it("refuses the bearer token for a Google account, which has an email but no password", async () => {
    users.push({
      id: ANON_UUID, email: "a@b.co", firstName: null, lastName: null,
      profileImageUrl: null, passwordHash: null,
    });
    const { req } = await run({ authorization: `Bearer ${ANON_UUID}` });
    expect(req.user).toBeUndefined();
  });
});

describe("input that is not a bearer UUID", () => {
  it("ignores a missing or non-Bearer Authorization header", async () => {
    expect((await run({})).req.user).toBeUndefined();
    expect((await run({ authorization: "Basic abc" })).req.user).toBeUndefined();
  });

  it("ignores a token that is not a UUID v4, without touching the database", async () => {
    for (const bad of ["not-a-uuid", "../../etc/passwd", "' OR 1=1 --", ANON_UUID.replace("4", "5")]) {
      const { req } = await run({ authorization: `Bearer ${bad}` });
      expect(req.user).toBeUndefined();
    }
    expect(inserted).toEqual([]);
  });
});

describe("the session cookie still takes priority", () => {
  it("authenticates from a valid session and never consults the bearer token", async () => {
    sessionResult.value = { user: { id: "real-user", email: "a@b.co" } };
    users.push({ id: OTHER_UUID, email: null, firstName: null, lastName: null, profileImageUrl: null });
    const { req } = await run({ authorization: `Bearer ${OTHER_UUID}` }, { sid: "session-id" });
    expect(req.user?.id).toBe("real-user");
  });
});

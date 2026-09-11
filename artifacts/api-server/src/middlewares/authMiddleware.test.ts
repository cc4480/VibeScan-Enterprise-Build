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
    select: () => ({
      from: () => ({
        where: (p: { val: unknown }) => Promise.resolve(users.filter((u) => u.id === p.val)),
      }),
    }),
  },
}));

const sessionResult: { value: unknown } = { value: null };
vi.mock("../lib/auth", () => ({
  getSession: () => Promise.resolve(sessionResult.value),
}));

const { authMiddleware } = await import("./authMiddleware");

const ANON_UUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const OTHER_UUID = "9c858901-8a57-4791-81fe-4c455b099bc9";

function run(headers: Record<string, string>, cookies: Record<string, string> = {}) {
  const req = { headers, cookies } as any;
  const next = vi.fn();
  return authMiddleware(req, {} as any, next).then(() => ({ req, next }));
}

beforeEach(() => {
  users.length = 0;
  inserted.length = 0;
  sessionResult.value = null;
  delete process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"];
});

afterEach(() => {
  delete process.env["ALLOW_LEGACY_ANONYMOUS_BEARER"];
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

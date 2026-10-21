import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * The gate decides whether we are allowed to send attack traffic at somebody.
 * Every case below is a way that decision could go wrong in a direction that
 * matters: attacking an unverified host, or an error being read as consent.
 *
 * The database is a small in-memory stand-in that EVALUATES the where-clause the
 * gate builds (eq / gt / and), rather than returning canned rows. So a query that
 * forgot the userId or the domain predicate would return the wrong row here and
 * fail the cross-user and cross-domain cases, instead of passing silently.
 * The real Postgres behaviour (including the expiry boundary) is covered by
 * domainVerification.integration.test.ts, including its cross-user case
 * ("does not let one user's verification unlock another user's scan").
 */

type Pred =
  | { op: "and"; parts: Pred[] }
  | { op: "eq"; col: string; val: unknown }
  | { op: "gt"; col: string; val: unknown };

type Row = { id: string; user_id: string; domain: string; verified_at: Date | null };

const state = vi.hoisted(() => ({
  table: [] as Row[],
  wheres: [] as unknown[],
  throws: false,
}));

vi.mock("@workspace/db", () => {
  const evaluate = (row: Row, p: Pred): boolean => {
    if (p.op === "and") return p.parts.every((q) => evaluate(row, q));
    const cell = row[p.col as keyof Row];
    if (p.op === "eq") return cell === p.val;
    // gt: a NULL column never compares greater, as in SQL.
    if (!(cell instanceof Date) || !(p.val instanceof Date)) return false;
    return cell.getTime() > p.val.getTime();
  };
  const chain = {
    from: () => chain,
    where: (p: Pred) => {
      state.wheres.push(p);
      return chain;
    },
    limit: (n: number) => {
      if (state.throws) return Promise.reject(new Error("connection lost"));
      const pred = state.wheres[state.wheres.length - 1] as Pred;
      const rows = state.table.filter((r) => evaluate(r, pred)).map((r) => ({ id: r.id })).slice(0, n);
      return Promise.resolve(rows);
    },
  };
  return {
    db: { select: () => chain },
    domainVerificationsTable: {
      id: "id",
      userId: "user_id",
      domain: "domain",
      verifiedAt: "verified_at",
    },
  };
});

vi.mock("./logger", () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn() },
}));

vi.mock("drizzle-orm", () => ({
  and: (...parts: Pred[]): Pred => ({ op: "and", parts }),
  eq: (col: string, val: unknown): Pred => ({ op: "eq", col, val }),
  gt: (col: string, val: unknown): Pred => ({ op: "gt", col, val }),
}));

const ENV_KEYS = ["ALLOW_UNVERIFIED_ACTIVE_PROBES", "DEV_SKIP_DOMAIN_VERIFICATION", "NODE_ENV"] as const;
const saved: Record<string, string | undefined> = {};

const NOW = new Date("2026-10-05T12:00:00.000Z");
const DAY = 86_400_000;

/** Put a verification row in the stand-in table. */
function seed(userId: string, domain: string, verifiedAt: Date | null = new Date()) {
  state.table.push({ id: `${userId}:${domain}`, user_id: userId, domain, verified_at: verifiedAt });
}

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  state.table.length = 0;
  state.wheres.length = 0;
  state.throws = false;
});

afterEach(() => {
  vi.useRealTimers();
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

async function unlocked(userId: string, url: string): Promise<boolean> {
  const { activeProbesUnlocked } = await import("./activeProbeGate.js");
  return activeProbesUnlocked(userId, url);
}

/** The predicates of the last query, flattened to { col: value } for the equality tests. */
function lastEqualities(): Record<string, unknown> {
  const pred = state.wheres[state.wheres.length - 1] as Pred;
  const parts = pred.op === "and" ? pred.parts : [pred];
  return Object.fromEntries(parts.flatMap((p) => (p.op === "eq" ? [[p.col, p.val]] : [])));
}

describe("activeProbesUnlocked", () => {
  it("denies a domain the user has not verified", async () => {
    expect(await unlocked("user-1", "https://example.com/app")).toBe(false);
  });

  it("allows a domain the same user has verified", async () => {
    seed("user-1", "myapp.example.com");
    expect(await unlocked("user-1", "https://myapp.example.com/login")).toBe(true);
  });

  it("filters on both the user and the domain", async () => {
    seed("user-1", "example.com");
    expect(await unlocked("user-1", "https://example.com/app")).toBe(true);

    const where = lastEqualities();
    expect(where).toMatchObject({ user_id: "user-1", domain: "example.com" });
  });

  it("fails closed for another user's verification of the same domain", async () => {
    // The row exists and is current, but it belongs to someone else.
    seed("user-2", "example.com");
    expect(await unlocked("user-1", "https://example.com/app")).toBe(false);
  });

  it("fails closed for the same user's verification of a different domain", async () => {
    seed("user-1", "other.example.com");
    expect(await unlocked("user-1", "https://example.com/app")).toBe(false);
  });

  it("denies when the database errors, rather than failing open", async () => {
    seed("user-1", "example.com");
    state.throws = true;
    expect(await unlocked("user-1", "https://example.com")).toBe(false);
  });

  it("denies a target URL it cannot parse", async () => {
    seed("user-1", "example.com");
    expect(await unlocked("user-1", "http://")).toBe(false);
  });

  it("unlocks everything when the operator flag is set", async () => {
    process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "true";
    expect(await unlocked("user-1", "https://anything.example.com/")).toBe(true);
    expect(state.wheres).toHaveLength(0);
  });

  it("honours the dev flag outside production", async () => {
    process.env.DEV_SKIP_DOMAIN_VERIFICATION = "true";
    process.env.NODE_ENV = "development";
    expect(await unlocked("user-1", "https://anything.example.com/")).toBe(true);
  });

  it("ignores the dev flag in production", async () => {
    process.env.DEV_SKIP_DOMAIN_VERIFICATION = "true";
    process.env.NODE_ENV = "production";
    expect(await unlocked("user-1", "https://anything.example.com/")).toBe(false);
  });

  it("treats any value other than the literal 'true' as off", async () => {
    process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "1";
    expect(await unlocked("user-1", "https://anything.example.com/")).toBe(false);
  });
});

/**
 * A verification expires VERIFICATION_VALID_DAYS after the proof was last seen.
 * The comparison is SQL (`verified_at > cutoff`); the stand-in evaluates it, so
 * these tests see the expiry through the same predicate the gate sends.
 */
describe("activeProbesUnlocked: verification expiry", () => {
  it("keeps the validity window at 14 days", async () => {
    const { VERIFICATION_VALID_DAYS } = await import("./domainVerify.js");
    expect(VERIFICATION_VALID_DAYS).toBe(14);
  });

  it("asks the database for verifications newer than now minus 14 days", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    seed("user-1", "example.com", new Date(NOW.getTime() - DAY));

    expect(await unlocked("user-1", "https://example.com/app")).toBe(true);

    const pred = state.wheres[0] as Pred;
    const parts = pred.op === "and" ? pred.parts : [pred];
    const gt = parts.find((p): p is Extract<Pred, { op: "gt" }> => p.op === "gt");
    expect(gt?.col).toBe("verified_at");
    expect((gt?.val as Date).getTime()).toBe(NOW.getTime() - 14 * DAY);
  });

  it("moves the cutoff with the clock, so a row ages out as time passes", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    seed("user-1", "example.com", new Date(NOW.getTime() - 13 * DAY));
    expect(await unlocked("user-1", "https://example.com")).toBe(true);

    vi.setSystemTime(new Date(NOW.getTime() + 10 * DAY));
    expect(await unlocked("user-1", "https://example.com")).toBe(false);
  });

  it("denies a row whose proof is older than the window", async () => {
    seed("user-1", "example.com", new Date(NOW.getTime() - 15 * DAY));
    expect(await unlocked("user-1", "https://example.com")).toBe(false);
  });

  it("denies a row that was never verified", async () => {
    seed("user-1", "example.com", null);
    expect(await unlocked("user-1", "https://example.com")).toBe(false);
  });

  it("applies no expiry when the operator has unlocked the instance", async () => {
    process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "true";
    expect(await unlocked("user-1", "https://example.com")).toBe(true);
    expect(state.wheres).toHaveLength(0);
  });
});

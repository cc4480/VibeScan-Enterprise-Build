import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * The gate decides whether we are allowed to send attack traffic at somebody.
 * Every case below is a way that decision could go wrong in a direction that
 * matters: attacking an unverified host, or an error being read as consent.
 */

// One mutable result the fake drizzle chain resolves to, so each test can say
// what the database "found" without rebuilding the chain.
const dbResult: { rows: unknown[]; throws: boolean } = { rows: [], throws: false };

vi.mock("@workspace/db", () => {
  const chain = {
    from: () => chain,
    where: () => chain,
    limit: () => {
      if (dbResult.throws) return Promise.reject(new Error("connection lost"));
      return Promise.resolve(dbResult.rows);
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

// The where-clause the gate builds, recorded so a test can read the expiry
// cutoff off it. Real drizzle would hand back opaque SQL objects.
const gtCalls: unknown[][] = [];

vi.mock("drizzle-orm", () => ({
  and: (...a: unknown[]) => a,
  eq: (...a: unknown[]) => a,
  gt: (...a: unknown[]) => {
    gtCalls.push(a);
    return a;
  },
}));

const ENV_KEYS = ["ALLOW_UNVERIFIED_ACTIVE_PROBES", "DEV_SKIP_DOMAIN_VERIFICATION", "NODE_ENV"] as const;
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  dbResult.rows = [];
  dbResult.throws = false;
  gtCalls.length = 0;
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

describe("activeProbesUnlocked", () => {
  it("denies a domain the user has not verified", async () => {
    dbResult.rows = [];
    expect(await unlocked("user-1", "https://example.com/app")).toBe(false);
  });

  it("allows a domain with a verified row", async () => {
    dbResult.rows = [{ id: "verification-1" }];
    expect(await unlocked("user-1", "https://myapp.example.com/login")).toBe(true);
  });

  it("denies when the database errors, rather than failing open", async () => {
    dbResult.throws = true;
    expect(await unlocked("user-1", "https://example.com")).toBe(false);
  });

  it("denies a target URL it cannot parse", async () => {
    dbResult.rows = [{ id: "verification-1" }];
    expect(await unlocked("user-1", "http://")).toBe(false);
  });

  it("unlocks everything when the operator flag is set", async () => {
    process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "true";
    dbResult.rows = [];
    expect(await unlocked("user-1", "https://anything.example.com/")).toBe(true);
  });

  it("honours the dev flag outside production", async () => {
    process.env.DEV_SKIP_DOMAIN_VERIFICATION = "true";
    process.env.NODE_ENV = "development";
    dbResult.rows = [];
    expect(await unlocked("user-1", "https://anything.example.com/")).toBe(true);
  });

  it("ignores the dev flag in production", async () => {
    process.env.DEV_SKIP_DOMAIN_VERIFICATION = "true";
    process.env.NODE_ENV = "production";
    dbResult.rows = [];
    expect(await unlocked("user-1", "https://anything.example.com/")).toBe(false);
  });

  it("treats any value other than the literal 'true' as off", async () => {
    process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "1";
    dbResult.rows = [];
    expect(await unlocked("user-1", "https://anything.example.com/")).toBe(false);
  });
});

/**
 * A verification expires VERIFICATION_VALID_DAYS after the proof was last seen.
 * The comparison itself is SQL (`verified_at > cutoff`), so these pin the cutoff
 * the gate hands the database; the boundary behaviour against a real Postgres is
 * in domainVerification.integration.test.ts.
 */
describe("activeProbesUnlocked: verification expiry", () => {
  const NOW = new Date("2026-10-05T12:00:00.000Z");
  const DAY = 86_400_000;

  it("keeps the validity window at 14 days", async () => {
    const { VERIFICATION_VALID_DAYS } = await import("./domainVerify.js");
    expect(VERIFICATION_VALID_DAYS).toBe(14);
  });

  it("asks the database for verifications newer than now minus 14 days", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    dbResult.rows = [{ id: "verification-1" }];

    expect(await unlocked("user-1", "https://example.com/app")).toBe(true);

    expect(gtCalls).toHaveLength(1);
    const [column, cutoff] = gtCalls[0] as [string, Date];
    expect(column).toBe("verified_at");
    expect(cutoff).toBeInstanceOf(Date);
    expect(cutoff.getTime()).toBe(NOW.getTime() - 14 * DAY);
  });

  it("moves the cutoff with the clock, so a row ages out as time passes", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    await unlocked("user-1", "https://example.com");
    vi.setSystemTime(new Date(NOW.getTime() + 10 * DAY));
    await unlocked("user-1", "https://example.com");

    const cutoffs = gtCalls.map((c) => (c[1] as Date).getTime());
    expect(cutoffs[1]! - cutoffs[0]!).toBe(10 * DAY);
  });

  it("denies when the database finds no verification inside the window", async () => {
    // The lapsed row is excluded by the SQL; all the gate sees is an empty result.
    dbResult.rows = [];
    expect(await unlocked("user-1", "https://example.com")).toBe(false);
  });

  it("applies no expiry when the operator has unlocked the instance", async () => {
    process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES = "true";
    expect(await unlocked("user-1", "https://example.com")).toBe(true);
    expect(gtCalls).toHaveLength(0);
  });
});

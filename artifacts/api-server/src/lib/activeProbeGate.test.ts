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

vi.mock("drizzle-orm", () => ({
  and: (...a: unknown[]) => a,
  eq: (...a: unknown[]) => a,
  isNotNull: (...a: unknown[]) => a,
}));

const ENV_KEYS = ["ALLOW_UNVERIFIED_ACTIVE_PROBES", "DEV_SKIP_DOMAIN_VERIFICATION", "NODE_ENV"] as const;
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  dbResult.rows = [];
  dbResult.throws = false;
});

afterEach(() => {
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

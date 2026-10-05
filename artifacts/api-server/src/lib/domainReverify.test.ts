import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * The re-verification pass, with the proof check and the database faked.
 *
 * What it has to get right: a row whose proof is still there is moved forward,
 * one whose proof is gone is NOT (that is what lets it lapse), one domain
 * blowing up does not take the others down, and the pass stays bounded. The SQL
 * (which rows are due, in what order) runs against a real Postgres in
 * domainVerification.integration.test.ts.
 */

interface Row {
  id: string;
  domain: string;
  token: string;
}

const state = {
  rows: [] as Row[],
  limitSeen: undefined as number | undefined,
  updates: [] as { set: Record<string, unknown>; id: unknown }[],
  /** ids whose UPDATE should throw */
  failUpdateFor: new Set<string>(),
  selectThrows: false,
};

vi.mock("@workspace/db", () => {
  const selectChain = {
    from: () => selectChain,
    where: () => selectChain,
    orderBy: () => selectChain,
    limit: (n: number) => {
      state.limitSeen = n;
      if (state.selectThrows) return Promise.reject(new Error("db down"));
      return Promise.resolve(state.rows.slice(0, n));
    },
  };
  return {
    db: {
      select: () => selectChain,
      update: () => ({
        set: (set: Record<string, unknown>) => ({
          where: (cond: { val: unknown }) => {
            if (state.failUpdateFor.has(cond.val as string)) return Promise.reject(new Error("write failed"));
            state.updates.push({ set, id: cond.val });
            return Promise.resolve();
          },
        }),
      }),
    },
    domainVerificationsTable: {
      id: "id",
      domain: "domain",
      token: "token",
      verifiedAt: "verified_at",
      lastCheckedAt: "last_checked_at",
    },
  };
});

vi.mock("drizzle-orm", () => ({
  and: (...a: unknown[]) => a,
  or: (...a: unknown[]) => a,
  eq: (col: unknown, val: unknown) => ({ col, val }),
  lt: (...a: unknown[]) => a,
  isNull: (...a: unknown[]) => a,
  isNotNull: (...a: unknown[]) => a,
  sql: (...a: unknown[]) => a,
}));

const info = vi.fn();
const warn = vi.fn();
vi.mock("./logger", () => ({
  logger: { info: (...a: unknown[]) => info(...a), warn: (...a: unknown[]) => warn(...a), error: vi.fn(), debug: vi.fn() },
}));

const defaultCheck = vi.fn();
vi.mock("./domainVerify", () => ({
  runVerificationCheck: (...a: unknown[]) => defaultCheck(...a),
}));

const NOW = new Date("2026-10-05T04:15:00.000Z");

const mk = (n: number): Row[] =>
  Array.from({ length: n }, (_, i) => ({ id: `id-${i}`, domain: `d${i}.example.com`, token: `tok-${i}` }));

beforeEach(() => {
  state.rows = [];
  state.limitSeen = undefined;
  state.updates = [];
  state.failUpdateFor = new Set();
  state.selectThrows = false;
  info.mockClear();
  warn.mockClear();
  defaultCheck.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

async function run(opts: Parameters<typeof import("./domainReverify.js").reverifyDomains>[0]) {
  const { reverifyDomains } = await import("./domainReverify.js");
  return reverifyDomains({ now: NOW, ...opts });
}

describe("reverifyDomains", () => {
  it("moves verifiedAt forward for a row whose proof is still there, and records how it passed", async () => {
    state.rows = mk(1);
    const verify = vi.fn().mockResolvedValue("well_known");

    const res = await run({ verify });

    expect(verify).toHaveBeenCalledWith("d0.example.com", "tok-0");
    expect(res).toEqual({ refreshed: 1, failed: 0, errored: 0, capped: false });
    expect(state.updates).toEqual([
      { id: "id-0", set: { verifiedAt: NOW, lastCheckedAt: NOW, method: "well_known" } },
    ]);
  });

  it("leaves verifiedAt alone for a row whose proof is gone, so it can lapse", async () => {
    state.rows = mk(1);

    const res = await run({ verify: vi.fn().mockResolvedValue(null) });

    expect(res).toEqual({ refreshed: 0, failed: 1, errored: 0, capped: false });
    expect(state.updates).toHaveLength(1);
    // Only the bookkeeping timestamp moves. Neither verifiedAt nor method may be written.
    expect(state.updates[0]!.set).toEqual({ lastCheckedAt: NOW });
    expect(state.updates[0]!.set).not.toHaveProperty("verifiedAt");
  });

  it("handles a mixed batch, each row on its own result", async () => {
    state.rows = mk(4);
    const verify = vi.fn(async (domain: string) => (domain === "d1.example.com" || domain === "d3.example.com" ? null : "dns"));

    const res = await run({ verify });

    expect(res).toEqual({ refreshed: 2, failed: 2, errored: 0, capped: false });
    const refreshedIds = state.updates.filter((u) => "verifiedAt" in u.set).map((u) => u.id).sort();
    expect(refreshedIds).toEqual(["id-0", "id-2"]);
  });

  it("isolates a check that throws: the other domains are still processed", async () => {
    state.rows = mk(4);
    const verify = vi.fn(async (domain: string) => {
      if (domain === "d1.example.com") throw new Error("DNS exploded");
      return "dns" as const;
    });

    const res = await run({ verify });

    expect(verify).toHaveBeenCalledTimes(4);
    expect(res).toEqual({ refreshed: 3, failed: 0, errored: 1, capped: false });
    // The one that threw was not touched at all.
    expect(state.updates.map((u) => u.id).sort()).toEqual(["id-0", "id-2", "id-3"]);
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ domain: "d1.example.com" }), expect.any(String));
  });

  it("isolates a failing database write the same way", async () => {
    state.rows = mk(3);
    state.failUpdateFor.add("id-0");

    const res = await run({ verify: vi.fn().mockResolvedValue("dns") });

    expect(res).toEqual({ refreshed: 2, failed: 0, errored: 1, capped: false });
    expect(state.updates.map((u) => u.id).sort()).toEqual(["id-1", "id-2"]);
  });

  it("stops at the per-run cap and says so", async () => {
    state.rows = mk(7);
    const verify = vi.fn().mockResolvedValue("dns");

    const res = await run({ verify, maxPerRun: 3 });

    expect(verify).toHaveBeenCalledTimes(3);
    expect(res).toEqual({ refreshed: 3, failed: 0, errored: 0, capped: true });
    // One extra row is read to learn that the cap bit.
    expect(state.limitSeen).toBe(4);
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ checked: 3, capped: true }), expect.any(String));
  });

  it("is not capped when exactly the cap is due", async () => {
    state.rows = mk(3);
    const res = await run({ verify: vi.fn().mockResolvedValue("dns"), maxPerRun: 3 });
    expect(res.capped).toBe(false);
    expect(res.refreshed).toBe(3);
  });

  it("never has more than the concurrency limit of checks in flight, and uses all of it", async () => {
    state.rows = mk(12);
    let inFlight = 0;
    let peak = 0;
    const verify = vi.fn(async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return "dns" as const;
    });

    const res = await run({ verify, concurrency: 5 });

    expect(res.refreshed).toBe(12);
    expect(peak).toBe(5);
  });

  it("defaults to a concurrency of 5", async () => {
    state.rows = mk(20);
    let inFlight = 0;
    let peak = 0;
    const verify = vi.fn(async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return null;
    });

    await run({ verify });

    expect(peak).toBe(5);
  });

  it("gives up on a check that hangs, counting it as errored instead of stalling the pass", async () => {
    vi.useFakeTimers();
    state.rows = mk(2);
    const verify = vi.fn(async (domain: string) => {
      if (domain === "d0.example.com") await new Promise(() => {}); // never settles
      return "dns" as const;
    });

    const pending = run({ verify });
    await vi.advanceTimersByTimeAsync(31_000);
    const res = await pending;

    expect(res).toEqual({ refreshed: 1, failed: 0, errored: 1, capped: false });
  });

  it("uses the same check the verify endpoint uses when none is injected", async () => {
    state.rows = mk(1);
    defaultCheck.mockResolvedValue("dns");

    const res = await run({});

    expect(defaultCheck).toHaveBeenCalledWith("d0.example.com", "tok-0");
    expect(res.refreshed).toBe(1);
  });

  it("logs the counts at info level", async () => {
    state.rows = mk(3);
    const verify = vi.fn(async (domain: string) => {
      if (domain === "d2.example.com") throw new Error("boom");
      return domain === "d1.example.com" ? null : ("dns" as const);
    });

    await run({ verify });

    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({ checked: 3, refreshed: 1, failed: 1, errored: 1 }),
      expect.any(String),
    );
  });

  it("does nothing, and runs no checks, when no row is due", async () => {
    const verify = vi.fn();
    const res = await run({ verify });
    expect(verify).not.toHaveBeenCalled();
    expect(res).toEqual({ refreshed: 0, failed: 0, errored: 0, capped: false });
  });

  it("lets a failure to load the rows propagate, so the job is recorded as failed", async () => {
    state.selectThrows = true;
    await expect(run({ verify: vi.fn() })).rejects.toThrow("db down");
  });
});

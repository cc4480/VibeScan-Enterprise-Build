import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * The cap decides who is allowed to spend our outbound bandwidth and AI budget,
 * so both directions of getting it wrong matter: locking out someone who has
 * scans left, and letting someone past who does not.
 *
 * The case that motivated these tests is the WHERE clause. Counting every row a
 * user owns rather than only the ones they asked for meant the monitor
 * scheduler — which rescans as often as every 3 days, plus a daily CVE sweep —
 * silently ate a subscriber's free scans and then told them they had used all
 * five themselves.
 */

// What the fake drizzle chain resolves to, plus the filters it was handed, so a
// test can assert on the query as well as the answer.
const dbState: { rows: unknown[]; lastWhere: unknown } = { rows: [], lastWhere: null };

vi.mock("@workspace/db", () => {
  // lastWhere is the scan-count query's filter; the lookups for a deleted account's carried usage
  // (users, deleted_account_trials) answer with no rows and must not overwrite it.
  let from: unknown = null;
  const chain = {
    from: (t: unknown) => {
      from = t;
      return chain;
    },
    where: (w: unknown) => {
      if (from === scansTable) {
        dbState.lastWhere = w;
        return Promise.resolve(dbState.rows);
      }
      return Promise.resolve([]);
    },
  };
  const scansTable = { userId: "user_id", origin: "origin", paidWith: "paid_with", createdAt: "created_at" };
  return {
    db: { select: () => chain },
    scansTable,
    usersTable: { id: "id", email: "email" },
    deletedAccountTrialsTable: { emailHash: "email_hash", periodStart: "period_start", scansUsed: "scans_used" },
  };
});

vi.mock("drizzle-orm", () => ({
  and: (...a: unknown[]) => ({ op: "and", args: a }),
  eq: (col: unknown, val: unknown) => ({ op: "eq", col, val }),
  or: (...a: unknown[]) => ({ op: "or", args: a }),
  gte: (col: unknown, val: unknown) => ({ op: "gte", col, val }),
  count: () => ({ op: "count" }),
  lt: (col: unknown, val: unknown) => ({ op: "lt", col, val }),
  sql: () => ({ op: "sql" }),
}));

const saved = process.env["FREE_TRIAL_SCAN_LIMIT"];

beforeEach(() => {
  vi.resetModules();
  delete process.env["FREE_TRIAL_SCAN_LIMIT"];
  dbState.rows = [];
  dbState.lastWhere = null;
});

afterEach(() => {
  if (saved === undefined) delete process.env["FREE_TRIAL_SCAN_LIMIT"];
  else process.env["FREE_TRIAL_SCAN_LIMIT"] = saved;
});

async function load() {
  return import("./freeTrial.js");
}

/** Every eq() the last query was built from, flattened out of and()/or(). */
function eqsInLastWhere(): Array<{ col: unknown; val: unknown }> {
  const out: Array<{ op: string; col: unknown; val: unknown }> = [];
  const walk = (n: any) => {
    if (!n) return;
    if (n.op === "eq") out.push(n);
    else if (n.op === "and" || n.op === "or") (n.args ?? []).forEach(walk);
  };
  walk(dbState.lastWhere);
  return out;
}

/** The or() inside the where — what makes a scan count. */
function orInLastWhere(): Array<{ col: unknown; val: unknown }> {
  const w = dbState.lastWhere as { op: string; args?: any[] } | null;
  const or = (w?.args ?? []).find((a) => a?.op === "or");
  return or?.args ?? [];
}

describe("trialScansUsedBy", () => {
  it("counts scans the user asked for, and any scan paid with a free scan — never the monitor's automatic ones", async () => {
    dbState.rows = [{ n: 2 }];
    const { trialScansUsedBy } = await load();

    expect(await trialScansUsedBy("user-1")).toBe(2);

    // A scan counts if the user started it, or if a free scan paid for it (a
    // non-subscriber's monitor baseline or "Scan now"). The scheduler's own
    // rescans are neither, so a subscriber's automation never spends the
    // allowance — the bug these tests were written for.
    expect(orInLastWhere()).toEqual([
      { op: "eq", col: "origin", val: "user" },
      { op: "eq", col: "paid_with", val: "free" },
    ]);
  });

  it("scopes the count to the one user", async () => {
    dbState.rows = [{ n: 1 }];
    const { trialScansUsedBy } = await load();
    await trialScansUsedBy("user-7");

    expect(eqsInLastWhere()).toEqual(
      expect.arrayContaining([{ op: "eq", col: "user_id", val: "user-7" }]),
    );
  });

  it("reads a user with no scans at all as zero", async () => {
    dbState.rows = [];
    const { trialScansUsedBy } = await load();
    expect(await trialScansUsedBy("nobody")).toBe(0);
  });
});

describe("trialScansExhausted", () => {
  it("allows a user below the limit", async () => {
    dbState.rows = [{ n: 1 }];
    const { trialScansExhausted } = await load();
    expect(await trialScansExhausted("user-1")).toBe(false);
  });

  it("allows the third free scan (the default is 3)", async () => {
    dbState.rows = [{ n: 2 }];
    const { trialScansExhausted } = await load();
    expect(await trialScansExhausted("user-1")).toBe(false);
  });

  it("refuses the scan that would be the fourth", async () => {
    dbState.rows = [{ n: 3 }];
    const { trialScansExhausted } = await load();
    expect(await trialScansExhausted("user-1")).toBe(true);
  });

  it("stays refused above the limit, rather than wrapping around", async () => {
    dbState.rows = [{ n: 9 }];
    const { trialScansExhausted } = await load();
    expect(await trialScansExhausted("user-1")).toBe(true);
  });

  it("honours an operator-raised limit", async () => {
    process.env["FREE_TRIAL_SCAN_LIMIT"] = "20";
    dbState.rows = [{ n: 5 }];
    const { trialScansExhausted } = await load();
    expect(await trialScansExhausted("user-1")).toBe(false);
  });

  it("names the same number in the message that it enforces", async () => {
    process.env["FREE_TRIAL_SCAN_LIMIT"] = "3";
    const { TRIAL_LIMIT_MESSAGE, FREE_TRIAL_SCAN_LIMIT } = await load();
    expect(FREE_TRIAL_SCAN_LIMIT).toBe(3);
    expect(TRIAL_LIMIT_MESSAGE).toContain("3 free scans");
  });
});

describe("the free scans renew every month", () => {
  /** The gte() the last query was built from: only scans from this month count. */
  function periodFilter(): { col: unknown; val: unknown } | undefined {
    const w = dbState.lastWhere as { args?: Array<{ op?: string; col?: unknown; val?: unknown }> } | null;
    return (w?.args ?? []).find((a) => a?.op === "gte") as { col: unknown; val: unknown } | undefined;
  }

  it("counts only scans since midnight UTC on the 1st of this month", async () => {
    const { trialScansUsedBy } = await load();
    dbState.rows = [{ n: 1 }];
    await trialScansUsedBy("user-1", new Date("2026-09-24T18:30:00Z"));
    const f = periodFilter();
    expect(f?.col).toBe("created_at");
    expect((f?.val as Date).toISOString()).toBe("2026-09-01T00:00:00.000Z");
  });

  it("starts a fresh allowance on the 1st", async () => {
    const { freeScanPeriodStart } = await load();
    expect(freeScanPeriodStart(new Date("2026-10-01T00:00:00Z")).toISOString()).toBe("2026-10-01T00:00:00.000Z");
    expect(freeScanPeriodStart(new Date("2026-09-30T23:59:59Z")).toISOString()).toBe("2026-09-01T00:00:00.000Z");
  });

  it("says when the allowance renews, rolling over the year end", async () => {
    const { freeScansResetAt } = await load();
    expect(freeScansResetAt(new Date("2026-09-24T12:00:00Z")).toISOString()).toBe("2026-10-01T00:00:00.000Z");
    expect(freeScansResetAt(new Date("2026-12-31T23:00:00Z")).toISOString()).toBe("2027-01-01T00:00:00.000Z");
  });
});

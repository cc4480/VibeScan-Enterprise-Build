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
  const chain = {
    from: () => chain,
    where: (w: unknown) => {
      dbState.lastWhere = w;
      return Promise.resolve(dbState.rows);
    },
  };
  return {
    db: { select: () => chain },
    scansTable: { userId: "user_id", origin: "origin", paidWith: "paid_with" },
  };
});

vi.mock("drizzle-orm", () => ({
  and: (...a: unknown[]) => ({ op: "and", args: a }),
  eq: (col: unknown, val: unknown) => ({ op: "eq", col, val }),
  or: (...a: unknown[]) => ({ op: "or", args: a }),
  count: () => ({ op: "count" }),
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

  it("refuses the scan that would be the third", async () => {
    dbState.rows = [{ n: 2 }];
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

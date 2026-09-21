import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Spending a credit is spending money someone paid, so the two ways to get it
 * wrong are not symmetric: charging twice for one scan takes money that was
 * never owed, and charging nothing lets the cap be walked past for free.
 *
 * The bug this shape exists to avoid is the lost update. Read the balance, then
 * write it back, and two scans submitted together both read 1, both write 0,
 * and both run — one of them free. So the predicate lives in the WHERE clause
 * and Postgres resolves it under the row lock; these tests assert that the
 * query is built that way, because the race itself cannot be reproduced against
 * a mock.
 */

const state: {
  where: unknown;
  set: Record<string, unknown> | null;
  returning: unknown[];
} = { where: null, set: null, returning: [] };

vi.mock("@workspace/db", () => {
  const chain: Record<string, unknown> = {};
  Object.assign(chain, {
    update: () => chain,
    select: () => chain,
    from: () => chain,
    set: (v: Record<string, unknown>) => {
      state.set = v;
      return chain;
    },
    where: (w: unknown) => {
      state.where = w;
      return chain;
    },
    returning: () => Promise.resolve(state.returning),
    then: (resolve: (v: unknown) => unknown) => resolve(state.returning),
  });
  return {
    db: chain,
    creditsTable: { userId: "credits.user_id", balance: "credits.balance", updatedAt: "credits.updated_at" },
  };
});

vi.mock("drizzle-orm", () => ({
  eq: (col: unknown, val: unknown) => ({ op: "eq", col, val }),
  and: (...args: unknown[]) => ({ op: "and", args }),
  gt: (col: unknown, val: unknown) => ({ op: "gt", col, val }),
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({
    op: "sql",
    text: strings.join("?"),
    values,
  }),
}));

function conditions(clause: unknown): Array<{ op: string; col?: unknown; val?: unknown }> {
  if (!clause || typeof clause !== "object") return [];
  const node = clause as { op?: string; args?: unknown[] };
  if (node.op === "and") return (node.args ?? []).flatMap(conditions);
  if (node.op) return [node as { op: string }];
  return [];
}

beforeEach(() => {
  state.where = null;
  state.set = null;
  state.returning = [];
  vi.resetModules();
});

describe("spendOneCredit", () => {
  it("returns the remaining balance when a credit was taken", async () => {
    state.returning = [{ balance: 4 }];
    const { spendOneCredit } = await import("./credits.js");
    expect(await spendOneCredit("user-1")).toBe(4);
  });

  it("returns null when there was nothing to take", async () => {
    // No row matched, because the balance was already 0. The caller must read
    // this as "refuse the scan", not as "spent the last one".
    state.returning = [];
    const { spendOneCredit } = await import("./credits.js");
    expect(await spendOneCredit("user-1")).toBeNull();
  });

  it("distinguishes spending the last credit from having none", async () => {
    // Both leave a balance of 0. Only one of them ran a scan, so they cannot
    // be allowed to look the same to the caller.
    state.returning = [{ balance: 0 }];
    const { spendOneCredit } = await import("./credits.js");
    expect(await spendOneCredit("user-1")).toBe(0);
  });

  it("guards on balance in the query, not in JavaScript", async () => {
    // The whole point. A `balance > 0` check performed after a read would be a
    // lost update under concurrency; performed in the WHERE clause it is
    // resolved by Postgres under the row lock.
    state.returning = [{ balance: 2 }];
    const { spendOneCredit } = await import("./credits.js");
    await spendOneCredit("user-1");

    const conds = conditions(state.where);
    expect(conds.some((c) => c.op === "gt" && c.col === "credits.balance" && c.val === 0)).toBe(true);
    expect(conds.some((c) => c.op === "eq" && c.col === "credits.user_id" && c.val === "user-1")).toBe(true);
  });

  it("decrements in the database rather than writing a value it computed", async () => {
    // set({ balance: read - 1 }) is the same lost update wearing a different
    // hat. The new value has to be derived by the database.
    state.returning = [{ balance: 1 }];
    const { spendOneCredit } = await import("./credits.js");
    await spendOneCredit("user-1");

    expect((state.set?.["balance"] as { op?: string })?.op).toBe("sql");
  });
});

describe("refundOneCredit", () => {
  it("adds the credit back for that user", async () => {
    const { refundOneCredit } = await import("./credits.js");
    await refundOneCredit("user-1");

    const conds = conditions(state.where);
    expect(conds.some((c) => c.op === "eq" && c.col === "credits.user_id" && c.val === "user-1")).toBe(true);
    expect((state.set?.["balance"] as { op?: string })?.op).toBe("sql");
  });

  it("carries no balance predicate, because it only ever undoes a spend", async () => {
    // A `balance > 0` guard here would silently fail to refund the user who
    // spent their last credit — exactly the person owed one back.
    const { refundOneCredit } = await import("./credits.js");
    await refundOneCredit("user-1");

    expect(conditions(state.where).some((c) => c.op === "gt")).toBe(false);
  });
});

describe("creditBalance", () => {
  it("reports 0 for a user who has never bought anything", async () => {
    state.returning = [];
    const { creditBalance } = await import("./credits.js");
    expect(await creditBalance("user-1")).toBe(0);
  });

  it("reports the stored balance", async () => {
    state.returning = [{ balance: 7 }];
    const { creditBalance } = await import("./credits.js");
    expect(await creditBalance("user-1")).toBe(7);
  });
});

/**
 * Spending a credit is spending money someone paid, so the two ways to get it wrong are not symmetric:
 * charging twice for one scan takes money that was never owed, and charging nothing lets the cap be walked
 * past for free.
 *
 * The bug this shape exists to avoid is the lost update. Read the balance, then write it back, and two scans
 * submitted together both read 1, both write 0, and both run: one of them free. Against a REAL Postgres
 * (BILLING_TEST_DATABASE_URL) the race itself can be run, rather than the query shape being inspected.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, makeUser } from "./realDb.testkit";

useRealDb();

dbSuiteOf(describe)("credits (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let credits: typeof import("./credits");
  const users: string[] = [];

  /** A user holding `balance` credits, or no credits row at all when balance is null. */
  async function userWith(balance: number | null) {
    const id = await makeUser(dbMod, "credits");
    users.push(id);
    if (balance !== null) await dbMod.db.insert(dbMod.creditsTable).values({ userId: id, balance });
    return id;
  }

  beforeAll(async () => {
    dbMod = await openDb();
    credits = await import("./credits");
  }, 60_000);

  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    if (users.length) {
      await dbMod.db.delete(dbMod.creditsTable).where(inArray(dbMod.creditsTable.userId, users));
      await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
    }
    await dbMod?.pool?.end?.();
  });

  describe("spendOneCredit", () => {
    it("returns the remaining balance when a credit was taken", async () => {
      const id = await userWith(5);
      expect(await credits.spendOneCredit(id)).toBe(4);
      expect(await credits.creditBalance(id)).toBe(4);
    });

    it("returns null when there was nothing to take, and does not go below zero", async () => {
      // The caller must read this as "refuse the scan", not as "spent the last one".
      const id = await userWith(0);
      expect(await credits.spendOneCredit(id)).toBeNull();
      expect(await credits.creditBalance(id)).toBe(0);
    });

    it("returns null for a user who has never bought anything", async () => {
      expect(await credits.spendOneCredit(await userWith(null))).toBeNull();
    });

    it("distinguishes spending the last credit from having none", async () => {
      // Both leave a balance of 0. Only one of them ran a scan, so they cannot look the same to the caller.
      const id = await userWith(1);
      expect(await credits.spendOneCredit(id)).toBe(0);
      expect(await credits.spendOneCredit(id)).toBeNull();
    });

    it("lets exactly as many concurrent spends succeed as there are credits", async () => {
      // The whole point. Twelve scans submitted at once against three credits: a read-then-write would let
      // several through on the same balance. The predicate in the WHERE clause is resolved under the row lock.
      const id = await userWith(3);
      const results = await Promise.all(Array.from({ length: 12 }, () => credits.spendOneCredit(id)));
      const taken = results.filter((r) => r !== null);
      expect(taken).toHaveLength(3);
      expect(taken.sort()).toEqual([0, 1, 2]); // each one saw a different remaining balance
      expect(await credits.creditBalance(id)).toBe(0);
    });
  });

  describe("refundOneCredit", () => {
    it("adds the credit back for that user, and only that user", async () => {
      const id = await userWith(2);
      const other = await userWith(2);
      await credits.refundOneCredit(id);
      expect(await credits.creditBalance(id)).toBe(3);
      expect(await credits.creditBalance(other)).toBe(2);
    });

    it("refunds the person who spent their last credit, because it carries no balance predicate", async () => {
      // A `balance > 0` guard here would silently fail to refund exactly the person owed one back.
      const id = await userWith(1);
      expect(await credits.spendOneCredit(id)).toBe(0);
      await credits.refundOneCredit(id);
      expect(await credits.creditBalance(id)).toBe(1);
    });

    it("keeps spends and refunds that land together, losing none", async () => {
      const id = await userWith(10);
      await Promise.all([
        ...Array.from({ length: 6 }, () => credits.spendOneCredit(id)),
        ...Array.from({ length: 4 }, () => credits.refundOneCredit(id)),
      ]);
      expect(await credits.creditBalance(id)).toBe(10 - 6 + 4);
    });
  });

  describe("creditBalance", () => {
    it("reports 0 for a user who has never bought anything", async () => {
      expect(await credits.creditBalance(await userWith(null))).toBe(0);
    });

    it("reports the stored balance", async () => {
      expect(await credits.creditBalance(await userWith(7))).toBe(7);
    });
  });
});

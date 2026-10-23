/**
 * The cap decides who is allowed to spend our outbound bandwidth and AI budget, so both directions of getting
 * it wrong matter: locking out someone who has scans left, and letting someone past who does not. Against a
 * REAL Postgres (BILLING_TEST_DATABASE_URL), with real scan rows.
 *
 * The case that motivated these tests is the WHERE clause. Counting every row a user owns rather than only the
 * ones they asked for meant the monitor scheduler, which rescans as often as every 3 days plus a daily CVE sweep,
 * silently ate a subscriber's free scans and then told them they had used all five themselves.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { dbSuiteOf, useRealDb, openDb, makeUser, uniqueEmail } from "./realDb.testkit";

useRealDb();
delete process.env["FREE_TRIAL_SCAN_LIMIT"]; // the default of 3, unless a test raises it

dbSuiteOf(describe)("free scan counting (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let trial: typeof import("./freeTrial");
  const users: string[] = [];

  /** A user with `count` scans of the given origin and payment, created at `at`. */
  async function userWith(scans: Array<{ n: number; origin?: "user" | "monitor" | "verify"; paidWith?: "free" | "included" | "credit"; at?: Date }>) {
    const id = await makeUser(dbMod, "trial-count");
    users.push(id);
    for (const s of scans) {
      for (let i = 0; i < s.n; i++) {
        await dbMod.db.insert(dbMod.scansTable).values({
          userId: id, userEmail: uniqueEmail("trial"), targetUrl: "https://trial.example/", tier: "deep", status: "complete",
          origin: s.origin ?? "user", ...(s.paidWith ? { paidWith: s.paidWith } : {}), ...(s.at ? { createdAt: s.at } : {}),
        });
      }
    }
    return id;
  }

  beforeAll(async () => {
    dbMod = await openDb();
    trial = await import("./freeTrial");
  }, 60_000);

  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    if (users.length) {
      await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, users));
      await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
    }
    await dbMod?.pool?.end?.();
  });

  describe("trialScansUsedBy", () => {
    it("counts scans the user asked for, and any scan paid with a free scan, never the monitor's automatic ones", async () => {
      // A scan counts if the user started it, or if a free scan paid for it (a non-subscriber's monitor baseline
      // or "Scan now"). The scheduler's own rescans are neither, so a subscriber's automation never spends the allowance.
      const id = await userWith([
        { n: 2, origin: "user" },
        { n: 1, origin: "monitor", paidWith: "free" },
        { n: 5, origin: "monitor", paidWith: "included" },
        { n: 4, origin: "monitor" },
      ]);
      expect(await trial.trialScansUsedBy(id)).toBe(3);
    });

    it("scopes the count to the one user", async () => {
      const mine = await userWith([{ n: 1 }]);
      await userWith([{ n: 6 }]);
      expect(await trial.trialScansUsedBy(mine)).toBe(1);
    });

    it("reads a user with no scans at all as zero", async () => {
      expect(await trial.trialScansUsedBy(await userWith([]))).toBe(0);
    });
  });

  describe("trialScansExhausted", () => {
    it("allows a user below the limit", async () => {
      expect(await trial.trialScansExhausted(await userWith([{ n: 1 }]))).toBe(false);
    });

    it("allows the third free scan (the default is 3)", async () => {
      expect(await trial.trialScansExhausted(await userWith([{ n: 2 }]))).toBe(false);
    });

    it("refuses the scan that would be the fourth", async () => {
      expect(await trial.trialScansExhausted(await userWith([{ n: 3 }]))).toBe(true);
    });

    it("stays refused above the limit, rather than wrapping around", async () => {
      expect(await trial.trialScansExhausted(await userWith([{ n: 9 }]))).toBe(true);
    });

    it("names the same number in the message that it enforces", () => {
      expect(trial.FREE_TRIAL_SCAN_LIMIT).toBe(3);
      expect(trial.TRIAL_LIMIT_MESSAGE).toContain("3 free scans");
    });
  });

  describe("an operator-raised limit", () => {
    it("is honoured by a fresh load of the module", async () => {
      const id = await userWith([{ n: 5 }]);
      process.env["FREE_TRIAL_SCAN_LIMIT"] = "20";
      vi.resetModules();
      try {
        const raised = await import("./freeTrial");
        const raisedDb = await import("@workspace/db");
        expect(raised.FREE_TRIAL_SCAN_LIMIT).toBe(20);
        expect(await raised.trialScansExhausted(id)).toBe(false);
        await raisedDb.pool.end();
      } finally {
        delete process.env["FREE_TRIAL_SCAN_LIMIT"];
      }
    });
  });

  describe("the free scans renew every month", () => {
    it("counts only scans since midnight UTC on the 1st of this month", async () => {
      const id = await userWith([
        { n: 1, at: new Date("2026-08-31T23:59:59Z") }, // last month: not counted
        { n: 2, at: new Date("2026-09-01T00:00:00Z") },
        { n: 1, at: new Date("2026-09-20T09:00:00Z") },
      ]);
      expect(await trial.trialScansUsedBy(id, new Date("2026-09-24T18:30:00Z"))).toBe(3);
    });

    it("starts a fresh allowance on the 1st", async () => {
      const id = await userWith([{ n: 3, at: new Date("2026-09-15T12:00:00Z") }]);
      expect(await trial.trialScansUsedBy(id, new Date("2026-09-30T23:59:59Z"))).toBe(3);
      expect(await trial.trialScansUsedBy(id, new Date("2026-10-01T00:00:00Z"))).toBe(0);
      expect(trial.freeScanPeriodStart(new Date("2026-10-01T00:00:00Z")).toISOString()).toBe("2026-10-01T00:00:00.000Z");
      expect(trial.freeScanPeriodStart(new Date("2026-09-30T23:59:59Z")).toISOString()).toBe("2026-09-01T00:00:00.000Z");
    });

    it("says when the allowance renews, rolling over the year end", () => {
      expect(trial.freeScansResetAt(new Date("2026-09-24T12:00:00Z")).toISOString()).toBe("2026-10-01T00:00:00.000Z");
      expect(trial.freeScansResetAt(new Date("2026-12-31T23:00:00Z")).toISOString()).toBe("2027-01-01T00:00:00.000Z");
    });
  });
});

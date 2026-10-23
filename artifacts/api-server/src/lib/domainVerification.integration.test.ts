/**
 * Domain-verification expiry against a REAL Postgres (BILLING_TEST_DATABASE_URL):
 * the gate's date comparison and the re-verification pass's row selection are
 * SQL, so a mocked database would agree with whatever the code was written to do.
 *
 * Clears domain_verifications before each test: use a disposable database.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const DAY = 86_400_000;
const HOUR = 3_600_000;

suite("domain verification expiry (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let gate: typeof import("./activeProbeGate");
  let reverify: typeof import("./domainReverify");
  let badge: typeof import("./reportBadge");
  let seq = 0;

  const ago = (ms: number) => new Date(Date.now() - ms);
  const userId = () => `exp-user-${Date.now()}-${++seq}`;

  async function insert(
    over: Partial<typeof import("@workspace/db").domainVerificationsTable.$inferInsert> & { domain: string },
  ) {
    const [row] = await dbMod.db
      .insert(dbMod.domainVerificationsTable)
      .values({ userId: userId(), token: `tok-${over.domain}`, ...over })
      .returning();
    return row!;
  }

  async function reload(id: string) {
    const { eq } = await import("drizzle-orm");
    const [row] = await dbMod.db
      .select()
      .from(dbMod.domainVerificationsTable)
      .where(eq(dbMod.domainVerificationsTable.id, id));
    return row!;
  }

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    gate = await import("./activeProbeGate");
    reverify = await import("./domainReverify");
    badge = await import("./reportBadge");
  }, 60_000);

  beforeEach(async () => {
    await dbMod.db.delete(dbMod.domainVerificationsTable);
  });

  afterAll(async () => {
    await dbMod?.pool?.end?.();
  });

  describe("the gate", () => {
    it("unlocks a verification inside the 14-day window and refuses one outside it", async () => {
      const fresh = await insert({ domain: "fresh.example.com", method: "dns", verifiedAt: ago(1 * HOUR) });
      const nearEdge = await insert({ domain: "edge-in.example.com", method: "dns", verifiedAt: ago(14 * DAY - 2 * HOUR) });
      const justLapsed = await insert({ domain: "edge-out.example.com", method: "dns", verifiedAt: ago(14 * DAY + 2 * HOUR) });
      const old = await insert({ domain: "old.example.com", method: "dns", verifiedAt: ago(40 * DAY) });
      const never = await insert({ domain: "never.example.com" });

      expect(await gate.activeProbesUnlocked(fresh.userId, "https://fresh.example.com/app")).toBe(true);
      expect(await gate.activeProbesUnlocked(nearEdge.userId, "https://edge-in.example.com")).toBe(true);
      expect(await gate.activeProbesUnlocked(justLapsed.userId, "https://edge-out.example.com")).toBe(false);
      expect(await gate.activeProbesUnlocked(old.userId, "https://old.example.com")).toBe(false);
      expect(await gate.activeProbesUnlocked(never.userId, "https://never.example.com")).toBe(false);
    });

    it("does not let one user's verification unlock another user's scan", async () => {
      const row = await insert({ domain: "mine.example.com", method: "dns", verifiedAt: ago(HOUR) });
      expect(await gate.activeProbesUnlocked("someone-else", "https://mine.example.com")).toBe(false);
      expect(await gate.activeProbesUnlocked(row.userId, "https://mine.example.com")).toBe(true);
    });

    it("applies the same expiry to the badge issuer", async () => {
      const ok = await insert({ domain: "badge-ok.example.com", method: "dns", verifiedAt: ago(DAY) });
      const lapsed = await insert({ domain: "badge-lapsed.example.com", method: "dns", verifiedAt: ago(15 * DAY) });
      expect(await badge.domainVerifiedBy(ok.userId, "https://badge-ok.example.com")).toBe(true);
      expect(await badge.domainVerifiedBy(lapsed.userId, "https://badge-lapsed.example.com")).toBe(false);
    });

    it("unlocks again once the pass finds the proof for a lapsed row", async () => {
      const row = await insert({ domain: "back.example.com", method: "dns", verifiedAt: ago(30 * DAY), lastCheckedAt: ago(30 * DAY) });
      expect(await gate.activeProbesUnlocked(row.userId, "https://back.example.com")).toBe(false);

      await reverify.reverifyDomains({ verify: async () => "dns" });

      expect(await gate.activeProbesUnlocked(row.userId, "https://back.example.com")).toBe(true);
    });
  });

  describe("the re-verification pass", () => {
    it("refreshes rows whose proof is present, leaves the others, and ignores rows never verified", async () => {
      const passing = await insert({ domain: "pass.example.com", method: "dns", verifiedAt: ago(10 * DAY), lastCheckedAt: ago(10 * DAY) });
      const failing = await insert({ domain: "fail.example.com", method: "dns", verifiedAt: ago(10 * DAY), lastCheckedAt: ago(10 * DAY) });
      const pending = await insert({ domain: "pending.example.com" });
      const before = { fail: failing.verifiedAt!.getTime() };

      const asked: string[] = [];
      const res = await reverify.reverifyDomains({
        verify: async (domain) => {
          asked.push(domain);
          // The proof moved from a DNS record to a file; the row should record how it passes now.
          return domain === "pass.example.com" ? "well_known" : null;
        },
      });

      expect(res).toEqual({ refreshed: 1, failed: 1, errored: 0, capped: false });
      expect(asked.sort()).toEqual(["fail.example.com", "pass.example.com"]);

      const p = await reload(passing.id);
      expect(Date.now() - p.verifiedAt!.getTime()).toBeLessThan(60_000);
      expect(p.method).toBe("well_known");

      const f = await reload(failing.id);
      expect(f.verifiedAt!.getTime()).toBe(before.fail); // untouched: it will lapse on its own
      expect(Date.now() - f.lastCheckedAt!.getTime()).toBeLessThan(60_000);

      const n = await reload(pending.id);
      expect(n.verifiedAt).toBeNull();
      expect(n.lastCheckedAt).toBeNull();
    });

    it("lets a row with a failing proof lapse after 14 days of consecutive failures, and not before", async () => {
      // 13 days since the proof was last seen: still valid after a failing pass.
      const early = await insert({ domain: "early.example.com", method: "dns", verifiedAt: ago(13 * DAY), lastCheckedAt: ago(DAY) });
      // 15 days: lapsed, and a failing pass does not bring it back.
      const late = await insert({ domain: "late.example.com", method: "dns", verifiedAt: ago(15 * DAY), lastCheckedAt: ago(DAY) });

      await reverify.reverifyDomains({ verify: async () => null });

      expect(await gate.activeProbesUnlocked(early.userId, "https://early.example.com")).toBe(true);
      expect(await gate.activeProbesUnlocked(late.userId, "https://late.example.com")).toBe(false);
    });

    it("skips a row checked within the last 12 hours", async () => {
      const recent = await insert({ domain: "recent.example.com", method: "dns", verifiedAt: ago(2 * HOUR), lastCheckedAt: ago(2 * HOUR) });
      const due = await insert({ domain: "due.example.com", method: "dns", verifiedAt: ago(DAY), lastCheckedAt: ago(DAY) });

      const asked: string[] = [];
      await reverify.reverifyDomains({ verify: async (d) => (asked.push(d), "dns") });

      expect(asked).toEqual(["due.example.com"]);
      expect((await reload(recent.id)).verifiedAt!.getTime()).toBe(recent.verifiedAt!.getTime());
      expect((await reload(due.id)).verifiedAt!.getTime()).toBeGreaterThan(due.verifiedAt!.getTime());
    });

    it("checks the least recently checked rows first when the cap bites, and reaches the rest next pass", async () => {
      await insert({ domain: "a.example.com", method: "dns", verifiedAt: ago(5 * DAY), lastCheckedAt: ago(1 * DAY) });
      await insert({ domain: "b.example.com", method: "dns", verifiedAt: ago(5 * DAY), lastCheckedAt: ago(3 * DAY) });
      await insert({ domain: "c.example.com", method: "dns", verifiedAt: ago(5 * DAY), lastCheckedAt: null });
      await insert({ domain: "d.example.com", method: "dns", verifiedAt: ago(5 * DAY), lastCheckedAt: ago(2 * DAY) });

      const first: string[] = [];
      const r1 = await reverify.reverifyDomains({ verify: async (d) => (first.push(d), null), maxPerRun: 2, concurrency: 1 });
      expect(r1.capped).toBe(true);
      expect(first).toEqual(["c.example.com", "b.example.com"]); // never-checked first, then oldest

      // Both were stamped, so even though they failed they go behind the ones not yet reached.
      const second: string[] = [];
      const r2 = await reverify.reverifyDomains({ verify: async (d) => (second.push(d), null), maxPerRun: 2, concurrency: 1 });
      expect(r2.capped).toBe(false);
      expect(second).toEqual(["d.example.com", "a.example.com"]);
    });

    it("survives one row's check throwing and still refreshes the rest", async () => {
      const boom = await insert({ domain: "boom.example.com", method: "dns", verifiedAt: ago(3 * DAY), lastCheckedAt: ago(3 * DAY) });
      const fine = await insert({ domain: "fine.example.com", method: "dns", verifiedAt: ago(3 * DAY), lastCheckedAt: ago(3 * DAY) });

      const res = await reverify.reverifyDomains({
        verify: async (d) => {
          if (d === "boom.example.com") throw new Error("resolver blew up");
          return "dns";
        },
      });

      expect(res).toMatchObject({ refreshed: 1, failed: 0, errored: 1 });
      expect((await reload(boom.id)).verifiedAt!.getTime()).toBe(boom.verifiedAt!.getTime());
      expect((await reload(fine.id)).verifiedAt!.getTime()).toBeGreaterThan(fine.verifiedAt!.getTime());
    });
  });
});

/**
 * The second factor of a password sign-in, against a REAL Postgres (BILLING_TEST_DATABASE_URL).
 *
 * A six-digit code is a million values, walkable in seconds, so it is only a credential because of three
 * properties. Each one has a test here that fails loudly if it is removed:
 *
 *   1. A code is matched inside a CHALLENGE, never on its own value.
 *   2. Five wrong guesses spend the challenge, correct code or not.
 *   3. A new challenge retires the user's earlier ones.
 *
 * What is being tested IS the read-modify-write behaviour (attempts counted, challenges retired), so it runs
 * against the real table: a stand-in that always answers "here is your row" would pass whether or not attempts
 * were ever counted.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, makeUser } from "./realDb.testkit";

useRealDb();

dbSuiteOf(describe)("pending login challenges (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let mod: typeof import("./pendingLogin");
  let MAX: number;
  const users: string[] = [];
  const newUser = async (tag: string) => {
    const id = await makeUser(dbMod, tag);
    users.push(id);
    return id;
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    mod = await import("./pendingLogin");
    ({ LOGIN_CODE_MAX_ATTEMPTS: MAX } = await import("./loginCode"));
  }, 60_000);

  afterAll(async () => {
    const { inArray } = await import("drizzle-orm");
    if (users.length) {
      await dbMod.db.delete(dbMod.pendingLoginsTable).where(inArray(dbMod.pendingLoginsTable.userId, users));
      await dbMod.db.delete(dbMod.usersTable).where(inArray(dbMod.usersTable.id, users));
    }
    await dbMod?.pool?.end?.();
  });

  describe("issuing a challenge", () => {
    it("returns a six-digit code and an opaque challenge, storing neither raw", async () => {
      const userId = await newUser("pl-issue");
      const { challenge, code } = await mod.issueLoginChallenge(userId);
      expect(code).toMatch(/^\d{6}$/);
      expect(challenge.length).toBeGreaterThan(20);
      const rows = await dbMod.db.select().from(dbMod.pendingLoginsTable).where(eq(dbMod.pendingLoginsTable.userId, userId));
      expect(rows).toHaveLength(1);
      // What lands in the table must not be usable to sign in.
      expect(rows[0]!.codeHash).not.toBe(code);
      expect(rows[0]!.challengeHash).not.toBe(challenge);
      expect(JSON.stringify(rows)).not.toContain(code);
      expect(JSON.stringify(rows)).not.toContain(challenge);
    });

    // Property 3. Several live codes for one account would divide the odds of a blind guess by the number outstanding.
    it("retires the user's previous challenge", async () => {
      const userId = await newUser("pl-retire");
      const first = await mod.issueLoginChallenge(userId);
      const second = await mod.issueLoginChallenge(userId);
      expect((await mod.redeemLoginChallenge(first.challenge, first.code)).ok).toBe(false);
      expect((await mod.redeemLoginChallenge(second.challenge, second.code)).ok).toBe(true);
    });

    it("does not retire a DIFFERENT user's challenge", async () => {
      const mine = await mod.issueLoginChallenge(await newUser("pl-mine"));
      await mod.issueLoginChallenge(await newUser("pl-other"));
      expect((await mod.redeemLoginChallenge(mine.challenge, mine.code)).ok).toBe(true);
    });
  });

  describe("redeeming a challenge", () => {
    it("signs in with the right code and returns the owning user", async () => {
      const userId = await newUser("pl-ok");
      const { challenge, code } = await mod.issueLoginChallenge(userId);
      expect(await mod.redeemLoginChallenge(challenge, code)).toEqual({ ok: true, userId });
    });

    it("is single-use", async () => {
      const { challenge, code } = await mod.issueLoginChallenge(await newUser("pl-once"));
      expect((await mod.redeemLoginChallenge(challenge, code)).ok).toBe(true);
      expect((await mod.redeemLoginChallenge(challenge, code)).ok).toBe(false);
    });

    // Property 1, and the reason this is two-factor at all. Holding a code without the challenge means holding
    // nothing: the challenge is what a correct password buys.
    it("refuses a valid code presented against another user's challenge", async () => {
      const victim = await mod.issueLoginChallenge(await newUser("pl-victim"));
      const attacker = await mod.issueLoginChallenge(await newUser("pl-attacker"));
      expect((await mod.redeemLoginChallenge(attacker.challenge, victim.code)).ok).toBe(false);
      // And the victim's own challenge is untouched by that attempt.
      expect((await mod.redeemLoginChallenge(victim.challenge, victim.code)).ok).toBe(true);
    });

    it("refuses a code with no challenge at all", async () => {
      const { code } = await mod.issueLoginChallenge(await newUser("pl-nochallenge"));
      expect((await mod.redeemLoginChallenge("", code)).ok).toBe(false);
      expect((await mod.redeemLoginChallenge("not-a-real-challenge", code)).ok).toBe(false);
    });

    // Property 2. Without this a million values fall in minutes.
    it("dies after five wrong guesses, refusing the CORRECT code afterwards", async () => {
      const { challenge, code } = await mod.issueLoginChallenge(await newUser("pl-guess"));
      const wrong = code === "000000" ? "111111" : "000000";
      for (let i = 0; i < MAX; i++) {
        expect(await mod.redeemLoginChallenge(challenge, wrong)).toEqual({ ok: false, reason: "invalid" });
      }
      expect(await mod.redeemLoginChallenge(challenge, code)).toEqual({ ok: false, reason: "too_many_attempts" });
    });

    it("counts guesses that arrive together, so a burst cannot walk past the limit", async () => {
      // Thirty wrong guesses fired at once. With a read-then-write count they would all read the same attempts
      // and all be allowed; counted in the database, the challenge is spent and the right code is refused.
      const { challenge, code } = await mod.issueLoginChallenge(await newUser("pl-burst"));
      const wrong = code === "000000" ? "111111" : "000000";
      await Promise.all(Array.from({ length: 30 }, () => mod.redeemLoginChallenge(challenge, wrong)));
      expect(await mod.redeemLoginChallenge(challenge, code)).toEqual({ ok: false, reason: "too_many_attempts" });
    });

    it("does not charge an attempt against a different challenge", async () => {
      const a = await mod.issueLoginChallenge(await newUser("pl-a"));
      const b = await mod.issueLoginChallenge(await newUser("pl-b"));
      await mod.redeemLoginChallenge(a.challenge, "000000");
      await mod.redeemLoginChallenge(a.challenge, "000000");
      // b's own attempts are still zero, so its code still works.
      expect((await mod.redeemLoginChallenge(b.challenge, b.code)).ok).toBe(true);
    });

    it("refuses an expired challenge, and says so distinctly for the log", async () => {
      const userId = await newUser("pl-expired");
      const { challenge, code } = await mod.issueLoginChallenge(userId);
      await dbMod.db.update(dbMod.pendingLoginsTable).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(dbMod.pendingLoginsTable.userId, userId));
      expect(await mod.redeemLoginChallenge(challenge, code)).toEqual({ ok: false, reason: "expired" });
    });
  });

  describe("abandoning challenges", () => {
    // Someone who knew the OLD password could be holding a live challenge from seconds ago; a password reset that
    // only evicts sessions would leave them one emailed code away from a fresh one.
    it("kills a live challenge so a reset password cannot be bypassed", async () => {
      const userId = await newUser("pl-abandon");
      const { challenge, code } = await mod.issueLoginChallenge(userId);
      await mod.abandonLoginChallenges(userId);
      expect((await mod.redeemLoginChallenge(challenge, code)).ok).toBe(false);
    });

    it("leaves other users' challenges alone", async () => {
      const other = await mod.issueLoginChallenge(await newUser("pl-keep"));
      await mod.abandonLoginChallenges(await newUser("pl-gone"));
      expect((await mod.redeemLoginChallenge(other.challenge, other.code)).ok).toBe(true);
    });
  });
});

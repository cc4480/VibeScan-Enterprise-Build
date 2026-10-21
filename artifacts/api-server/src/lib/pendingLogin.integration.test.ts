/**
 * The second-factor attempt cap against a REAL Postgres. The race is between
 * concurrent statements, which a mocked db cannot reproduce. Skips unless a
 * throwaway database is supplied (see freeTrial.integration.test.ts).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("2FA attempt cap (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let pending: typeof import("./pendingLogin");
  let loginCode: typeof import("./loginCode");
  let drizzle: typeof import("drizzle-orm");

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    pending = await import("./pendingLogin");
    loginCode = await import("./loginCode");
    drizzle = await import("drizzle-orm");
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });

  async function freshChallenge() {
    const userId = `pl-${Math.random().toString(36).slice(2)}`;
    const issued = await pending.issueLoginChallenge(userId);
    return { ...issued, userId };
  }
  const wrongFor = (code: string) => (code === "000000" ? "111111" : "000000");

  it("refuses more than the cap when guesses arrive together", async () => {
    const { challenge, code } = await freshChallenge();
    const wrong = wrongFor(code);

    const results = await Promise.all(
      Array.from({ length: 12 }, () => pending.redeemLoginChallenge(challenge, wrong)),
    );

    // Exactly the cap is compared; the rest are refused without being compared.
    expect(results.filter((r) => !r.ok && r.reason === "invalid")).toHaveLength(loginCode.LOGIN_CODE_MAX_ATTEMPTS);
    expect(results.filter((r) => !r.ok && r.reason === "too_many_attempts")).toHaveLength(12 - loginCode.LOGIN_CODE_MAX_ATTEMPTS);
    expect(results.some((r) => r.ok)).toBe(false);

    const [row] = await dbMod.db
      .select({ attempts: dbMod.pendingLoginsTable.attempts })
      .from(dbMod.pendingLoginsTable)
      .where(drizzle.eq(dbMod.pendingLoginsTable.challengeHash, loginCode.hashValue(challenge)));
    expect(row?.attempts).toBe(loginCode.LOGIN_CODE_MAX_ATTEMPTS);

    // Once spent, even the right code is refused.
    expect(await pending.redeemLoginChallenge(challenge, code)).toEqual({ ok: false, reason: "too_many_attempts" });
  });

  it("still accepts the right code within the cap", async () => {
    const { challenge, code, userId } = await freshChallenge();
    const wrong = wrongFor(code);
    for (let i = 0; i < loginCode.LOGIN_CODE_MAX_ATTEMPTS - 1; i++) {
      expect(await pending.redeemLoginChallenge(challenge, wrong)).toEqual({ ok: false, reason: "invalid" });
    }

    expect(await pending.redeemLoginChallenge(challenge, code)).toEqual({ ok: true, userId });
  });

  it("does not let the right code through twice when it races itself", async () => {
    const { challenge, code } = await freshChallenge();
    const results = await Promise.all(Array.from({ length: 5 }, () => pending.redeemLoginChallenge(challenge, code)));

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });
});

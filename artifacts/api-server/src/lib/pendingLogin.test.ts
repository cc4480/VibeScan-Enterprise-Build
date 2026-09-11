import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The second factor of a password sign-in.
 *
 * A six-digit code is a million values — walkable in seconds — so it is only a
 * credential because of three properties. Each one has a test here that fails
 * loudly if it is removed:
 *
 *   1. A code is matched inside a CHALLENGE, never on its own value.
 *   2. Five wrong guesses spend the challenge, correct code or not.
 *   3. A new challenge retires the user's earlier ones.
 *
 * The database is faked with a real in-memory table rather than a stub that
 * returns canned rows, because what is being tested IS the read-modify-write
 * behaviour — a mock that always answers "here is your row" would pass whether
 * or not attempts were ever counted.
 */

interface Row {
  id: string;
  userId: string;
  challengeHash: string;
  codeHash: string;
  attempts: number;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

const rows: Row[] = [];
let nextId = 1;

type Pred =
  | { op: "eq"; col: string; val: unknown }
  | { op: "isNull"; col: string }
  | { op: "and"; parts: Pred[] };

function matches(row: Row, p: Pred): boolean {
  if (p.op === "eq") return (row as unknown as Record<string, unknown>)[p.col] === p.val;
  if (p.op === "isNull") return (row as unknown as Record<string, unknown>)[p.col] == null;
  return p.parts.every((part) => matches(row, part));
}

vi.mock("drizzle-orm", () => ({
  eq: (col: string, val: unknown) => ({ op: "eq", col, val }),
  isNull: (col: string) => ({ op: "isNull", col }),
  and: (...parts: Pred[]) => ({ op: "and", parts }),
}));

vi.mock("@workspace/db", () => ({
  pendingLoginsTable: {
    id: "id",
    userId: "userId",
    challengeHash: "challengeHash",
    codeHash: "codeHash",
    attempts: "attempts",
    expiresAt: "expiresAt",
    usedAt: "usedAt",
  },
  db: {
    insert: () => ({
      values: (v: Partial<Row>) => {
        rows.push({
          id: String(nextId++),
          attempts: 0,
          usedAt: null,
          createdAt: new Date(),
          ...v,
        } as Row);
        return Promise.resolve();
      },
    }),
    select: () => ({
      from: () => ({
        where: (p: Pred) => Promise.resolve(rows.filter((r) => matches(r, p))),
      }),
    }),
    update: () => ({
      set: (changes: Partial<Row>) => ({
        where: (p: Pred) => {
          const hit = rows.filter((r) => matches(r, p));
          for (const r of hit) Object.assign(r, changes);
          const result = Promise.resolve(hit) as Promise<Row[]> & { returning: () => Promise<Row[]> };
          result.returning = () => Promise.resolve(hit);
          return result;
        },
      }),
    }),
  },
}));

const { issueLoginChallenge, redeemLoginChallenge, abandonLoginChallenges } = await import("./pendingLogin");
const { LOGIN_CODE_MAX_ATTEMPTS } = await import("./loginCode");

beforeEach(() => {
  rows.length = 0;
  nextId = 1;
});

describe("issuing a challenge", () => {
  it("returns a six-digit code and an opaque challenge, storing neither raw", async () => {
    const { challenge, code } = await issueLoginChallenge("user-1");
    expect(code).toMatch(/^\d{6}$/);
    expect(challenge.length).toBeGreaterThan(20);
    // What lands in the table must not be usable to sign in.
    expect(rows[0]!.codeHash).not.toBe(code);
    expect(rows[0]!.challengeHash).not.toBe(challenge);
    expect(JSON.stringify(rows)).not.toContain(code);
    expect(JSON.stringify(rows)).not.toContain(challenge);
  });

  // Property 3. Several live codes for one account would divide the odds of a
  // blind guess by the number outstanding.
  it("retires the user's previous challenge", async () => {
    const first = await issueLoginChallenge("user-1");
    const second = await issueLoginChallenge("user-1");

    expect((await redeemLoginChallenge(first.challenge, first.code)).ok).toBe(false);
    expect((await redeemLoginChallenge(second.challenge, second.code)).ok).toBe(true);
  });

  it("does not retire a DIFFERENT user's challenge", async () => {
    const mine = await issueLoginChallenge("user-1");
    await issueLoginChallenge("user-2");
    expect((await redeemLoginChallenge(mine.challenge, mine.code)).ok).toBe(true);
  });
});

describe("redeeming a challenge", () => {
  it("signs in with the right code and returns the owning user", async () => {
    const { challenge, code } = await issueLoginChallenge("user-1");
    expect(await redeemLoginChallenge(challenge, code)).toEqual({ ok: true, userId: "user-1" });
  });

  it("is single-use", async () => {
    const { challenge, code } = await issueLoginChallenge("user-1");
    expect((await redeemLoginChallenge(challenge, code)).ok).toBe(true);
    expect((await redeemLoginChallenge(challenge, code)).ok).toBe(false);
  });

  // Property 1, and the reason this is two-factor at all. Holding a code
  // without the challenge means holding nothing: the challenge is what a
  // correct password buys.
  it("refuses a valid code presented against another user's challenge", async () => {
    const victim = await issueLoginChallenge("victim");
    const attacker = await issueLoginChallenge("attacker");
    expect((await redeemLoginChallenge(attacker.challenge, victim.code)).ok).toBe(false);
    // And the victim's own challenge is untouched by that attempt.
    expect((await redeemLoginChallenge(victim.challenge, victim.code)).ok).toBe(true);
  });

  it("refuses a code with no challenge at all", async () => {
    const { code } = await issueLoginChallenge("user-1");
    expect((await redeemLoginChallenge("", code)).ok).toBe(false);
    expect((await redeemLoginChallenge("not-a-real-challenge", code)).ok).toBe(false);
  });

  // Property 2. Without this a million values fall in minutes.
  it("dies after five wrong guesses, refusing the CORRECT code afterwards", async () => {
    const { challenge, code } = await issueLoginChallenge("user-1");
    const wrong = code === "000000" ? "111111" : "000000";

    for (let i = 0; i < LOGIN_CODE_MAX_ATTEMPTS; i++) {
      const r = await redeemLoginChallenge(challenge, wrong);
      expect(r).toEqual({ ok: false, reason: "invalid" });
    }

    expect(await redeemLoginChallenge(challenge, code)).toEqual({
      ok: false,
      reason: "too_many_attempts",
    });
  });

  it("does not charge an attempt against a different challenge", async () => {
    const a = await issueLoginChallenge("user-1");
    const b = await issueLoginChallenge("user-2");
    await redeemLoginChallenge(a.challenge, "000000");
    await redeemLoginChallenge(a.challenge, "000000");
    // b's own attempts are still zero, so its code still works.
    expect((await redeemLoginChallenge(b.challenge, b.code)).ok).toBe(true);
  });

  it("refuses an expired challenge, and says so distinctly for the log", async () => {
    const { challenge, code } = await issueLoginChallenge("user-1");
    rows[0]!.expiresAt = new Date(Date.now() - 1000);
    expect(await redeemLoginChallenge(challenge, code)).toEqual({ ok: false, reason: "expired" });
  });
});

describe("abandoning challenges", () => {
  // Someone who knew the OLD password could be holding a live challenge from
  // seconds ago; a password reset that only evicts sessions would leave them
  // one emailed code away from a fresh one.
  it("kills a live challenge so a reset password cannot be bypassed", async () => {
    const { challenge, code } = await issueLoginChallenge("user-1");
    await abandonLoginChallenges("user-1");
    expect((await redeemLoginChallenge(challenge, code)).ok).toBe(false);
  });

  it("leaves other users' challenges alone", async () => {
    const other = await issueLoginChallenge("user-2");
    await abandonLoginChallenges("user-1");
    expect((await redeemLoginChallenge(other.challenge, other.code)).ok).toBe(true);
  });
});

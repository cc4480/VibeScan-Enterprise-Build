/**
 * POST /dismissals: the field limits and the per-account cap, against a REAL Postgres.
 * Skips unless a throwaway database is supplied (see freeTrial.integration.test.ts).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("dismissals: limits and cap (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let drizzle: typeof import("drizzle-orm");
  let post: (req: unknown, res: unknown) => Promise<void>;
  let cap: number;

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    drizzle = await import("drizzle-orm");
    const mod = await import("./dismissals");
    cap = mod.DISMISSAL_CAP_PER_USER;
    const router = mod.default as unknown as {
      stack: { route?: { path: string; methods: Record<string, boolean>; stack: { handle: unknown }[] } }[];
    };
    const layer = router.stack.find((l) => l.route?.path === "/dismissals" && l.route.methods["post"]);
    const handlers = layer!.route!.stack;
    post = handlers[handlers.length - 1]!.handle as typeof post;
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });

  function send(userId: string, body: Record<string, unknown>) {
    const res = { statusCode: 200, body: null as unknown, status(c: number) { this.statusCode = c; return this; }, json(b: unknown) { this.body = b; return this; } };
    const req = { body, isAuthenticated: () => true, user: { id: userId }, log: { error() {}, info() {} } };
    return post(req, res).then(() => res);
  }
  const base = (over: Record<string, unknown> = {}) => ({
    targetUrl: "https://limits.example.com/",
    findingName: "Missing HSTS",
    findingCategory: "HTTP Security",
    findingEvidence: "header absent",
    ...over,
  });

  it("refuses a target URL past 2048 characters and accepts one at the limit", async () => {
    const userId = `dl-url-${Date.now()}`;
    const longPath = "a".repeat(2048 - "https://limits.example.com/".length + 1);
    expect((await send(userId, base({ targetUrl: `https://limits.example.com/${longPath}` }))).statusCode).toBe(400);
    const atLimit = `https://limits.example.com/${"a".repeat(2048 - "https://limits.example.com/".length)}`;
    expect(atLimit.length).toBe(2048);
    expect((await send(userId, base({ targetUrl: atLimit }))).statusCode).toBe(201);
  });

  it("refuses over-long names, evidence and reasons", async () => {
    const userId = `dl-fields-${Date.now()}`;
    expect((await send(userId, base({ findingName: "n".repeat(201) }))).statusCode).toBe(400);
    expect((await send(userId, base({ findingCategory: "c".repeat(201) }))).statusCode).toBe(400);
    expect((await send(userId, base({ findingEvidence: "e".repeat(2001) }))).statusCode).toBe(400);
    expect((await send(userId, base({ reason: "r".repeat(501) }))).statusCode).toBe(400);
    expect((await send(userId, base({ findingEvidence: "e".repeat(2000) }))).statusCode).toBe(201);
  });

  it("refuses a new dismissal once the account holds the cap, with a clear code", async () => {
    const userId = `dl-cap-${Date.now()}`;
    const { dismissedFindingsTable } = dbMod;
    const { findingFingerprint, canonicalizeTargetUrl } = await import("../lib/fingerprint");
    const target = canonicalizeTargetUrl("https://cap.example.com/");
    const held = { category: "HTTP Security", name: "Missing HSTS", evidence: "header absent" };
    const rows = Array.from({ length: cap - 1 }, (_, i) => ({
      userId,
      targetUrl: target,
      findingFingerprint: `fp-${i}`,
      findingName: "seeded",
      findingCategory: "seeded",
      reason: "false_positive",
    }));
    rows.push({
      userId,
      targetUrl: target,
      findingFingerprint: findingFingerprint(held.category, held.name, held.evidence),
      findingName: held.name,
      findingCategory: held.category,
      reason: "false_positive",
    });
    for (let i = 0; i < rows.length; i += 500) await dbMod.db.insert(dismissedFindingsTable).values(rows.slice(i, i + 500));

    const refused = await send(userId, base({ targetUrl: "https://cap.example.com/", findingName: "one more" }));
    expect(refused.statusCode).toBe(409);
    expect(refused.body).toMatchObject({ code: "dismissal_limit" });

    // Re-dismissing a finding already held is not a new row, so it is still accepted at the cap.
    const again = await send(userId, base({ targetUrl: "https://cap.example.com/" }));
    expect(again.statusCode).toBe(201);

    const { eq, count } = drizzle;
    const [{ n }] = await dbMod.db.select({ n: count() }).from(dismissedFindingsTable).where(eq(dismissedFindingsTable.userId, userId));
    expect(Number(n)).toBe(cap);
    await dbMod.db.delete(dismissedFindingsTable).where(eq(dismissedFindingsTable.userId, userId));
  });
});

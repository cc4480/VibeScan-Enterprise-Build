/** The opt-out column against a REAL Postgres (BILLING_TEST_DATABASE_URL): default off, then set. */
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("AI analysis opt-out (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let optOut: typeof import("./aiOptOut");
  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    optOut = await import("./aiOptOut");
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });

  it("is not opted out by default, is once set, and an unknown user is not opted out", async () => {
    const { db, usersTable } = dbMod;
    const { eq } = await import("drizzle-orm");
    const [u] = await db.insert(usersTable).values({ email: `ai-${Date.now()}@example.com` }).returning({ id: usersTable.id });
    expect(await optOut.isAiAnalysisOptedOut(u!.id)).toBe(false);
    await db.update(usersTable).set({ aiAnalysisOptedOut: true }).where(eq(usersTable.id, u!.id));
    expect(await optOut.isAiAnalysisOptedOut(u!.id)).toBe(true);
    expect(await optOut.isAiAnalysisOptedOut("00000000-0000-0000-0000-000000000000")).toBe(false);
  });
});

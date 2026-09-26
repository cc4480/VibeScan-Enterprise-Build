/**
 * A paused monitor is skipped by every scheduled job, against a REAL Postgres: the skip is a
 * predicate in the query, which a mocked db would "pass" whatever it said. Skips unless a
 * throwaway database is supplied (BILLING_TEST_DATABASE_URL).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("paused monitors (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let scheduler: typeof import("./monitorScheduler");

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    scheduler = await import("./monitorScheduler");
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });

  it("returns a running monitor and leaves out a paused one, and resuming brings it back", async () => {
    const { db, monitorSubscriptionsTable, usersTable } = dbMod;
    const { eq } = await import("drizzle-orm");
    const [u] = await db.insert(usersTable).values({ email: `pause-${Date.now()}@example.com` }).returning({ id: usersTable.id });
    const expiresAt = new Date(Date.now() + 86_400_000);
    const base = { userId: u!.id, userEmail: "p@example.com", status: "active" as const, expiresAt };
    const [running] = await db.insert(monitorSubscriptionsTable).values({ ...base, targetUrl: "https://running.example.com" }).returning();
    const [paused] = await db.insert(monitorSubscriptionsTable).values({ ...base, targetUrl: "https://paused.example.com", pausedAt: new Date() }).returning();

    const ids = async () => (await scheduler.activeEntitledSubscriptions(new Date())).subs.map((s) => s.id);
    let seen = await ids();
    expect(seen).toContain(running!.id);
    expect(seen).not.toContain(paused!.id);

    await db.update(monitorSubscriptionsTable).set({ pausedAt: null }).where(eq(monitorSubscriptionsTable.id, paused!.id));
    seen = await ids();
    expect(seen).toContain(paused!.id);
  });
});

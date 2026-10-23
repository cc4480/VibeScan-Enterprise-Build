/** PATCH /monitor/subscriptions/:id/pause against a REAL Postgres (BILLING_TEST_DATABASE_URL). */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, uniqueEmail, type TestApp } from "../lib/realDb.testkit";

useRealDb();

dbSuiteOf(describe)("PATCH /monitor/subscriptions/:id/pause (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let app: TestApp;
  let owner: string;
  let stranger: string;
  const subIds: string[] = [];

  async function subscription(status: "active" | "cancelled" | "expired" = "active", pausedAt: Date | null = null) {
    const [s] = await dbMod.db
      .insert(dbMod.monitorSubscriptionsTable)
      .values({ userId: owner, userEmail: uniqueEmail("monitor"), targetUrl: "https://controls.example/", status, pausedAt, expiresAt: new Date(Date.now() + 86_400_000) })
      .returning({ id: dbMod.monitorSubscriptionsTable.id });
    subIds.push(s!.id);
    return s!.id;
  }
  const pausedAtOf = async (id: string) => {
    const [row] = await dbMod.db.select({ p: dbMod.monitorSubscriptionsTable.pausedAt }).from(dbMod.monitorSubscriptionsTable).where(eq(dbMod.monitorSubscriptionsTable.id, id));
    return row!.p;
  };
  const patch = (id: string, b: unknown) =>
    fetch(`${app.base}/monitor/subscriptions/${id}/pause`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    owner = await makeUser(dbMod, "controls-owner");
    stranger = await makeUser(dbMod, "controls-stranger");
    const { default: router } = await import("./monitorControls");
    app = startApp(router);
  }, 60_000);

  afterAll(async () => {
    app?.server.close();
    const { inArray } = await import("drizzle-orm");
    if (subIds.length) await dbMod.db.delete(dbMod.monitorSubscriptionsTable).where(inArray(dbMod.monitorSubscriptionsTable.id, subIds));
    for (const id of [owner, stranger]) if (id) await dbMod.db.delete(dbMod.usersTable).where(eq(dbMod.usersTable.id, id));
    await dbMod?.pool?.end?.();
  });

  it("pauses an active monitor and reports when", async () => {
    app.as({ id: owner });
    const id = await subscription();
    const res = await patch(id, { paused: true });
    expect(res.status).toBe(200);
    const j = (await res.json()) as { paused: boolean; pausedAt: string };
    expect(j.paused).toBe(true);
    expect(new Date(j.pausedAt).getTime()).toBeGreaterThan(Date.now() - 5000);
    expect(await pausedAtOf(id)).toBeInstanceOf(Date);
  });

  it("resumes by clearing the pause", async () => {
    app.as({ id: owner });
    const id = await subscription("active", new Date("2026-09-01"));
    const j = (await (await patch(id, { paused: false })).json()) as { paused: boolean };
    expect(j.paused).toBe(false);
    expect(await pausedAtOf(id)).toBeNull();
  });

  it("pausing twice keeps the original pause time", async () => {
    app.as({ id: owner });
    const earlier = new Date("2026-09-01T00:00:00Z");
    const id = await subscription("active", earlier);
    await patch(id, { paused: true });
    expect(await pausedAtOf(id)).toEqual(earlier);
  });

  it("looks the monitor up by id AND owner, so another customer's id is a 404, not a pause", async () => {
    const id = await subscription();
    app.as({ id: stranger });
    expect((await patch(id, { paused: true })).status).toBe(404);
    expect(await pausedAtOf(id)).toBeNull();
  });

  it("refuses a cancelled monitor", async () => {
    app.as({ id: owner });
    const id = await subscription("cancelled");
    expect((await patch(id, { paused: true })).status).toBe(409);
    expect(await pausedAtOf(id)).toBeNull();
  });

  it("rejects a body that is not a boolean, and a signed-out caller", async () => {
    const id = await subscription();
    app.as({ id: owner });
    expect((await patch(id, { paused: "yes" })).status).toBe(400);
    expect((await patch(id, {})).status).toBe(400);
    app.as(null);
    expect((await patch(id, { paused: true })).status).toBe(401);
    expect(await pausedAtOf(id)).toBeNull();
  });
});

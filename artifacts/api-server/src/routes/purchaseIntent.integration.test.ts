/**
 * "Tell me when I can buy more scans", against a REAL Postgres (BILLING_TEST_DATABASE_URL).
 *
 * The cap is currently a wall with nothing behind it, and this route is the only thing that notices somebody
 * walked into it wanting to pay. So the two failures that matter are losing the signal (an error the caller
 * swallows) and inflating it (one impatient person counted twice).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, startApp, uniqueEmail, type TestApp } from "../lib/realDb.testkit";

useRealDb();
delete process.env["FREE_TRIAL_SCAN_LIMIT"];

dbSuiteOf(describe)("/purchase-intent (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let app: TestApp;
  const owners: string[] = [];
  let n = 0;
  const person = () => {
    const id = `pi-${Date.now()}-${++n}`;
    owners.push(id);
    return { id, email: uniqueEmail("intent") };
  };
  const url = () => `${app.base}/purchase-intent`;
  const post = () => fetch(url(), { method: "POST" });
  const rowsOf = (id: string) => dbMod.db.select().from(dbMod.purchaseIntentsTable).where(eq(dbMod.purchaseIntentsTable.userId, id));

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    const { default: router } = await import("./purchaseIntent");
    app = startApp(router);
  }, 60_000);

  afterAll(async () => {
    app?.server.close();
    const { inArray } = await import("drizzle-orm");
    if (owners.length) {
      await dbMod.db.delete(dbMod.purchaseIntentsTable).where(inArray(dbMod.purchaseIntentsTable.userId, owners));
      await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, owners));
    }
    await dbMod?.pool?.end?.();
  });

  describe("POST", () => {
    it("records the signal with the address we would actually mail", async () => {
      const p = person();
      app.as(p);
      expect((await post()).status).toBe(201);
      expect(await rowsOf(p.id)).toMatchObject([{ userId: p.id, email: p.email }]);
    });

    it("counts one person once, however many times they press the button", async () => {
      // The insert is guarded by the unique user_id, not by the client behaving. Pressed together, too.
      const p = person();
      app.as(p);
      await Promise.all(Array.from({ length: 5 }, post));
      await post();
      expect(await rowsOf(p.id)).toHaveLength(1);
    });

    it("keeps the first press, which is when they wanted it", async () => {
      const p = person();
      app.as(p);
      await post();
      const first = (await rowsOf(p.id))[0]!.createdAt;
      await new Promise((r) => setTimeout(r, 25));
      app.as({ ...p, email: uniqueEmail("changed") });
      await post();
      const row = (await rowsOf(p.id))[0]!;
      expect(row.createdAt).toEqual(first);
      expect(row.email).toBe(p.email);
    });

    it("refuses an account with no address, rather than banking an unreachable signal", async () => {
      const p = person();
      app.as({ id: p.id, email: null });
      expect((await post()).status).toBe(400);
      expect(await rowsOf(p.id)).toHaveLength(0);
    });

    it("requires a session", async () => {
      app.as(null);
      expect((await post()).status).toBe(401);
    });

    it("reports a write failure instead of claiming success", async () => {
      // Telling someone they are on the list when the row never landed is the one outcome that loses the signal
      // silently. A NUL byte in the address is a value Postgres really refuses to store.
      const p = person();
      app.as({ id: p.id, email: "bad\u0000address@example.com" });
      expect((await post()).status).toBe(500);
      expect(await rowsOf(p.id)).toHaveLength(0);
    });
  });

  describe("GET", () => {
    it("says not-registered when there is no row, with the scans used and the limit", async () => {
      const p = person();
      app.as(p);
      for (let i = 0; i < 2; i++) {
        await dbMod.db.insert(dbMod.scansTable).values({ userId: p.id, userEmail: p.email, targetUrl: "https://intent.example/", tier: "deep", status: "complete" });
      }
      expect(await (await fetch(url())).json()).toMatchObject({ registered: false, scansUsed: 2, scanLimit: 3 });
    });

    it("says registered once a row exists", async () => {
      const p = person();
      app.as(p);
      await post();
      expect(await (await fetch(url())).json()).toMatchObject({ registered: true });
    });

    it("requires a session", async () => {
      app.as(null);
      expect((await fetch(url())).status).toBe(401);
    });
  });
});

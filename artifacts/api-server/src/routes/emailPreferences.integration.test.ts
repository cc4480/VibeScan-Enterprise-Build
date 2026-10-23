/**
 * Email preferences against a REAL Postgres (BILLING_TEST_DATABASE_URL).
 *
 * Preferences are stored as opt-OUTs and presented as opt-INs, because the default for
 * every flag is "send it" and a false default is what survives a new column being added.
 * That inversion happens once, in the route, so a bug here flips the meaning of every
 * toggle at once and the user's setting would silently mean the opposite of what they chose.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { dbSuiteOf, useRealDb, openDb, makeUser, startApp, type TestApp } from "../lib/realDb.testkit";

useRealDb();

dbSuiteOf(describe)("/account/email-preferences (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let app: TestApp;
  const users: string[] = [];
  const url = () => `${app.base}/account/email-preferences`;
  const get = async () => (await fetch(url())).json() as Promise<any>;
  const put = (b: unknown) => fetch(url(), { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });
  const fresh = async (tag: string) => {
    const id = await makeUser(dbMod, tag);
    users.push(id);
    app.as({ id });
    return id;
  };
  const row = async (id: string) => {
    const [r] = await dbMod.db.select().from(dbMod.usersTable).where(eq(dbMod.usersTable.id, id));
    return r!;
  };

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    const { default: router } = await import("./emailPreferences");
    app = startApp(router);
  }, 60_000);

  afterAll(async () => {
    app?.server.close();
    for (const id of users) await dbMod.db.delete(dbMod.usersTable).where(eq(dbMod.usersTable.id, id));
    await dbMod?.pool?.end?.();
  });

  describe("GET", () => {
    it("presents stored opt-outs as opt-ins", async () => {
      const id = await fresh("prefs-get");
      await dbMod.db
        .update(dbMod.usersTable)
        .set({ marketingOptedOut: true, notifyRegressionOptedOut: true, notifyMinSeverity: "high" })
        .where(eq(dbMod.usersTable.id, id));
      const body = await get();
      expect(body.productUpdates).toBe(false); // opted OUT of marketing
      expect(body.monitorAlerts).toBe(true);
      expect(body.alerts.cve).toBe(true);
      expect(body.alerts.regression).toBe(false); // opted OUT of regressions
      expect(body.minSeverity).toBe("high");
    });

    it("defaults a user nobody has touched to everything on, no floor", async () => {
      await fresh("prefs-default");
      const body = await get();
      expect(body.monitorAlerts).toBe(true);
      // Exhaustive on purpose. A new alert kind added without a default of "send it" would change
      // what existing users receive without anyone choosing that, and this makes the omission fail.
      expect(body.alerts).toEqual({ cve: true, regression: true, certExpiry: true, scanComplete: true, availability: true, drift: true });
      expect(body.minSeverity).toBe("info");
    });
  });

  describe("PUT", () => {
    it("stores the inverse of what the user asked to receive", async () => {
      const id = await fresh("prefs-put-inverse");
      await put({ alerts: { scanComplete: false } });
      // Asked NOT to receive scan_complete, so the opt-out column goes true.
      expect((await row(id)).notifyScanCompleteOptedOut).toBe(true);
    });

    it("stores the two pulse-check toggles in their own columns", async () => {
      // A toggle that animates and stores nothing is invisible to the compiler: the column name
      // is a string in an untyped update object. The real table is what proves each lands.
      const id = await fresh("prefs-put-pulse");
      await put({ alerts: { availability: false } });
      let r = await row(id);
      expect(r.notifyAvailabilityOptedOut).toBe(true);
      expect(r.notifyDriftOptedOut).toBe(false);
      await put({ alerts: { drift: false } });
      r = await row(id);
      expect(r.notifyDriftOptedOut).toBe(true);
    });

    it("changes only the fields supplied", async () => {
      // A settings screen sends one toggle at a time. Writing defaults for the others would
      // silently reset preferences the user never touched.
      const id = await fresh("prefs-put-partial");
      await dbMod.db.update(dbMod.usersTable).set({ notifyRegressionOptedOut: true, notifyMinSeverity: "low" }).where(eq(dbMod.usersTable.id, id));
      await put({ alerts: { cve: false } });
      const r = await row(id);
      expect(r.notifyCveOptedOut).toBe(true);
      expect(r.notifyRegressionOptedOut).toBe(true);
      expect(r.notifyMinSeverity).toBe("low");
    });

    it("accepts a valid severity floor", async () => {
      const id = await fresh("prefs-put-floor");
      const res = await put({ minSeverity: "medium" });
      expect(res.status).toBe(200);
      expect((await row(id)).notifyMinSeverity).toBe("medium");
    });

    it("REFUSES an unrecognised severity rather than storing it", async () => {
      // Coercing junk to a default would quietly decide which security alerts somebody stops
      // receiving, and nothing would report that it happened.
      const id = await fresh("prefs-put-junk");
      const before = (await row(id)).notifyMinSeverity;
      expect((await put({ minSeverity: "urgent" })).status).toBe(400);
      expect((await row(id)).notifyMinSeverity).toBe(before);
    });

    it("refuses a body with nothing to change", async () => {
      await fresh("prefs-put-empty");
      expect((await put({})).status).toBe(400);
    });

    it("refuses an unauthenticated caller before touching anything", async () => {
      const id = await fresh("prefs-put-anon");
      const before = (await row(id)).notifyMinSeverity;
      app.as(null);
      expect((await put({ minSeverity: "high" })).status).toBe(401);
      expect((await row(id)).notifyMinSeverity).toBe(before);
    });
  });

  describe("quiet hours", () => {
    const window = { start: 22, end: 7, timezone: "Europe/London" };

    it("is off by default, and saves, returns and clears a window", async () => {
      const id = await fresh("prefs-quiet");
      expect((await get()).quietHours).toBeNull();
      const saved = (await (await put({ quietHours: window })).json()) as any;
      expect(saved.quietHours).toEqual(window);
      expect((await get()).quietHours).toEqual(window);
      const r = await row(id);
      expect([r.quietHoursStart, r.quietHoursEnd, r.quietHoursTimezone]).toEqual([22, 7, "Europe/London"]);
      expect(((await (await put({ quietHours: null })).json()) as any).quietHours).toBeNull();
      const cleared = await row(id);
      expect([cleared.quietHoursStart, cleared.quietHoursEnd, cleared.quietHoursTimezone]).toEqual([null, null, null]);
    });

    it("is read back by the delivery check", async () => {
      const id = await fresh("prefs-quiet-read");
      await put({ quietHours: { start: 0, end: 23, timezone: "UTC" } });
      const { notificationPrefs } = await import("../lib/notificationPrefs");
      expect((await notificationPrefs(id)).quietHours).toEqual({ start: 0, end: 23, timezone: "UTC" });
    });

    it("rejects an incomplete, empty or invalid window and stores nothing", async () => {
      const id = await fresh("prefs-quiet-bad");
      for (const bad of [{}, { start: 22, end: 7 }, { start: 5, end: 5, timezone: "UTC" }, { start: 24, end: 7, timezone: "UTC" },
        { start: -1, end: 7, timezone: "UTC" }, { start: 1.5, end: 7, timezone: "UTC" }, { start: "22", end: 7, timezone: "UTC" },
        { start: 22, end: 7, timezone: "Not/AZone" }, { start: 22, end: 7, timezone: "" }, "nope"]) {
        expect((await put({ quietHours: bad })).status).toBe(400);
      }
      const r = await row(id);
      expect([r.quietHoursStart, r.quietHoursEnd, r.quietHoursTimezone]).toEqual([null, null, null]);
    });

    it("leaves a saved window alone when other preferences change", async () => {
      await fresh("prefs-quiet-keep");
      await put({ quietHours: window });
      const after = (await (await put({ minSeverity: "high" })).json()) as any;
      expect(after.quietHours).toEqual(window);
    });
  });
});

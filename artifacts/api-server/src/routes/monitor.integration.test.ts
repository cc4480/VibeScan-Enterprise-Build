/**
 * Monitoring over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): the real routes behind the real
 * guards, plan rows, credits, free-scan counts, SSRF check, job queue and report lookups. Nothing is stubbed.
 *
 * Covers creating a subscription (the sweep race, plan limits, the free site, paying for the baseline scan, seeding
 * from an earlier scan) and the per-subscription endpoints (ownership, and what the history reports).
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { dbSuiteOf, useRealDb, openDb, startApp, uniqueEmail, type TestApp } from "../lib/realDb.testkit";

useRealDb();
delete process.env["FREE_TRIAL_SCAN_LIMIT"]; // the default of three free scans

const DAY = 86_400_000;
const ENV = ["MONITORING_REQUIRES_PLAN", "FREE_MONITOR_SITES"] as const;

dbSuiteOf(describe)("monitoring (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let app: TestApp;
  let router: import("express").IRouter;
  let credits: typeof import("../lib/credits");
  let savedCf: string | undefined;
  const owners: string[] = [];
  const scanIds: string[] = [];
  let n = 0;

  /** An account that calls from an address of its own. */
  function person() {
    const id = `mon-${Date.now()}-${++n}`;
    owners.push(id);
    const ip = `198.51.${Math.floor(n / 250)}.${(n % 250) + 1}`;
    return { id, email: uniqueEmail("monitor"), ip };
  }
  type Person = ReturnType<typeof person>;
  const as = (p: Person | null) => app.as(p ? { id: p.id, email: p.email } : null);
  const call = (p: Person, method: string, path: string, body?: unknown) =>
    fetch(app.base + path, {
      method,
      headers: { "content-type": "application/json", "x-forwarded-for": p.ip },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  /** A loopback site nobody listens on: the SSRF check accepts it and the baseline scan has nothing to reach. */
  const site = () => `http://127.0.0.1:${9000 + ++n}`;
  const create = (p: Person, targetUrl: string) => call(p, "POST", "/monitor/subscriptions", { targetUrl });

  async function monitorRow(p: Person, targetUrl: string, status: "active" | "cancelled" = "active") {
    const [s] = await dbMod.db
      .insert(dbMod.monitorSubscriptionsTable)
      .values({ userId: p.id, userEmail: p.email, targetUrl, status, expiresAt: new Date(Date.now() + 365 * DAY) })
      .returning({ id: dbMod.monitorSubscriptionsTable.id });
    return s!.id;
  }
  const subsOf = (p: Person) => dbMod.db.select().from(dbMod.monitorSubscriptionsTable).where(eq(dbMod.monitorSubscriptionsTable.userId, p.id));
  const baselineScansOf = async (p: Person) =>
    (await dbMod.db.select().from(dbMod.scansTable).where(eq(dbMod.scansTable.userId, p.id))).filter((s) => s.origin === "monitor");
  const plan = (p: Person, fields: Partial<typeof dbMod.billingSubscriptionsTable.$inferInsert>) =>
    dbMod.db.insert(dbMod.billingSubscriptionsTable).values({ userId: p.id, plan: "solo", status: "active", urlLimit: 3, ...fields });
  const setCredits = (p: Person, balance: number) => dbMod.db.insert(dbMod.creditsTable).values({ userId: p.id, balance });
  /** Uses up the three free scans for the month. */
  async function exhaustFreeScans(p: Person) {
    for (let i = 0; i < 3; i++) {
      const [s] = await dbMod.db
        .insert(dbMod.scansTable)
        .values({ userId: p.id, userEmail: p.email, targetUrl: "https://used.example/", tier: "deep", status: "complete" })
        .returning({ id: dbMod.scansTable.id });
      scanIds.push(s!.id);
    }
  }
  /** A finished scan and its report for the user, on `targetUrl`. */
  async function report(p: Person, targetUrl: string, data: unknown, daysAgo = 0) {
    const at = new Date(Date.now() - daysAgo * DAY);
    const [s] = await dbMod.db
      .insert(dbMod.scansTable)
      .values({ userId: p.id, userEmail: p.email, targetUrl, tier: "deep", status: "complete", createdAt: at })
      .returning({ id: dbMod.scansTable.id });
    scanIds.push(s!.id);
    const [r] = await dbMod.db
      .insert(dbMod.reportsTable)
      .values({ scanId: s!.id, userId: p.id, targetUrl, tier: "deep", scannedAt: at, duration: 1, data: data as never })
      .returning({ id: dbMod.reportsTable.id });
    return { id: r!.id, scannedAt: at };
  }

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq } = await import("drizzle-orm"));
    credits = await import("../lib/credits");
    savedCf = process.env["BEHIND_CLOUDFLARE"];
    process.env["BEHIND_CLOUDFLARE"] = "true";
    router = (await import("./monitor")).default;
    app = startApp(router);
  }, 60_000);

  afterEach(() => {
    for (const k of ENV) delete process.env[k];
  });

  afterAll(async () => {
    app?.server.close();
    if (savedCf === undefined) delete process.env["BEHIND_CLOUDFLARE"];
    else process.env["BEHIND_CLOUDFLARE"] = savedCf;
    const { inArray } = await import("drizzle-orm");
    if (owners.length) {
      await dbMod.db.delete(dbMod.monitorSubscriptionsTable).where(inArray(dbMod.monitorSubscriptionsTable.userId, owners));
      await dbMod.db.delete(dbMod.billingSubscriptionsTable).where(inArray(dbMod.billingSubscriptionsTable.userId, owners));
      await dbMod.db.delete(dbMod.creditsTable).where(inArray(dbMod.creditsTable.userId, owners));
      await dbMod.db.delete(dbMod.reportsTable).where(inArray(dbMod.reportsTable.userId, owners));
      await dbMod.db.delete(dbMod.scansTable).where(inArray(dbMod.scansTable.userId, owners));
    }
    await dbMod?.pool?.end?.();
  });

  describe("POST /monitor/subscriptions: closing the race with the 6-hourly sweep", () => {
    it("sets a future nextScanAt at creation, so the sweep can't read a fresh subscription as already due", async () => {
      // Before this fix, a brand-new subscription had nextScanAt: null and lastScanAt: null until its baseline scan
      // finished: the exact shape isSubscriptionDue() treats as due. A sweep tick landing in that window enqueued a
      // second baseline scan for the same subscription.
      const p = person();
      as(p);
      const before = Date.now();
      expect((await create(p, site())).status).toBe(201);
      const [row] = await subsOf(p);
      expect(row!.nextScanAt).toBeInstanceOf(Date);
      // In the future, and past the point a same-day sweep tick could reach, not just "not null".
      expect(row!.nextScanAt!.getTime()).toBeGreaterThan(before + DAY);
    });
  });

  describe("POST /monitor/subscriptions: plan limits", () => {
    it("creates without complaint while enforcement is off, however many they already have", async () => {
      // The property that matters on the day this ships: MONITORING_REQUIRES_PLAN is unset in production, so an
      // existing user with any number of monitored sites must be unaffected.
      const p = person();
      as(p);
      for (let i = 0; i < 8; i++) await monitorRow(p, site());
      expect((await create(p, site())).status).toBe(201);
    });

    it("refuses once the caller is at their plan's URL limit, and creates nothing", async () => {
      process.env["MONITORING_REQUIRES_PLAN"] = "true";
      const p = person();
      as(p);
      await plan(p, { plan: "solo", urlLimit: 3 });
      for (let i = 0; i < 3; i++) await monitorRow(p, site());
      const res = await create(p, site());
      expect(res.status).toBe(403);
      expect(((await res.json()) as { code: string }).code).toBe("monitor_url_limit");
      expect(await subsOf(p)).toHaveLength(3); // the check is worthless if the row still lands
    });

    it("allows the last slot under the limit", async () => {
      // Guards the boundary: >= vs > is the classic off-by-one here, and getting it wrong sells someone three sites
      // and gives them two.
      process.env["MONITORING_REQUIRES_PLAN"] = "true";
      const p = person();
      as(p);
      await plan(p, { plan: "solo", urlLimit: 3 });
      for (let i = 0; i < 2; i++) await monitorRow(p, site());
      expect((await create(p, site())).status).toBe(201);
      expect(await subsOf(p)).toHaveLength(3);
    });

    it("refuses a paused plan before counting anything, and says the history survives", async () => {
      process.env["MONITORING_REQUIRES_PLAN"] = "true";
      const p = person();
      as(p);
      await plan(p, { plan: "studio", status: "paused", urlLimit: 10 });
      const res = await create(p, site());
      expect(res.status).toBe(403);
      const body = (await res.json()) as { code: string; error: string };
      expect(body.code).toBe("monitor_plan_required");
      // The message is the only place the user learns their history survives a lapse.
      expect(body.error).toContain("history");
    });

    it("does not count a cancelled monitor against the limit", async () => {
      process.env["MONITORING_REQUIRES_PLAN"] = "true";
      const p = person();
      as(p);
      await plan(p, { plan: "solo", urlLimit: 1 });
      await monitorRow(p, site(), "cancelled");
      expect((await create(p, site())).status).toBe(201);
    });

    it("refuses the same site twice, instead of watching it twice", async () => {
      const p = person();
      as(p);
      const url = site();
      expect((await create(p, url)).status).toBe(201);
      expect((await create(p, url)).status).toBe(409);
      expect((await subsOf(p)).filter((s) => s.status === "active")).toHaveLength(1);
    });

    it("does not let parallel creates exceed the plan's site limit", async () => {
      // The plan count and the insert run under a per-user lock; without it parallel creates all count one site
      // fewer than the limit and all insert.
      process.env["MONITORING_REQUIRES_PLAN"] = "true";
      const p = person();
      as(p);
      await plan(p, { plan: "solo", urlLimit: 2 });
      const results = await Promise.all(Array.from({ length: 5 }, () => create(p, site())) /* five is the per-account hourly limit */);
      expect(results.filter((r) => r.status === 201)).toHaveLength(2);
      expect(results.filter((r) => r.status === 403)).toHaveLength(3);
      expect((await subsOf(p)).filter((x) => x.status === "active")).toHaveLength(2);
    });

    it("does not create the same monitor twice when parallel creates name one URL", async () => {
      const p = person();
      as(p);
      await plan(p, { plan: "unlimited", urlLimit: 5 });
      const url = site();
      const results = await Promise.all(Array.from({ length: 4 }, () => create(p, url)));
      expect(results.filter((r) => r.status === 201)).toHaveLength(1);
      expect(results.filter((r) => r.status === 409)).toHaveLength(3);
      expect(await subsOf(p)).toHaveLength(1);
    });
  });

  // Once plans are enforced an account with no plan keeps one free site, so a person who tried the product has a
  // reason to come back. Unenforced (today) nothing here applies.
  describe("POST /monitor/subscriptions: the free site", () => {
    it("lets an account with no plan watch its first site", async () => {
      process.env["MONITORING_REQUIRES_PLAN"] = "true";
      const p = person();
      as(p);
      expect((await create(p, site())).status).toBe(201);
    });

    it("refuses a second site, and tells a free account where to go next", async () => {
      process.env["MONITORING_REQUIRES_PLAN"] = "true";
      const p = person();
      as(p);
      await monitorRow(p, site());
      const res = await create(p, site());
      expect(res.status).toBe(403);
      const body = (await res.json()) as { code: string; reason: string; error: string; urlLimit: number };
      expect(body.code).toBe("monitor_url_limit");
      // The UI keys on this to show the plans instead of "see your plan".
      expect(body.reason).toBe("free");
      expect(body.urlLimit).toBe(1);
      expect(body.error).toContain("free account");
      expect(await subsOf(p)).toHaveLength(1);
    });

    it("FREE_MONITOR_SITES=0 turns the free site off", async () => {
      process.env["MONITORING_REQUIRES_PLAN"] = "true";
      process.env["FREE_MONITOR_SITES"] = "0";
      const p = person();
      as(p);
      const res = await create(p, site());
      expect(res.status).toBe(403);
      expect(((await res.json()) as { code: string }).code).toBe("monitor_plan_required");
    });
  });

  // Adding a monitor runs a full deep scan straight away. Without a plan it is charged like any other scan. It used
  // to demand a free scan specifically, so a customer who had bought credits could not add a single monitor.
  describe("POST /monitor/subscriptions: paying for the baseline scan", () => {
    it("takes a free scan for the baseline while there is one", async () => {
      const p = person();
      as(p);
      expect((await create(p, site())).status).toBe(201);
      expect((await baselineScansOf(p))[0]?.paidWith).toBe("free");
    });

    it("lets a credit holder add a monitor once the free scans are gone, paying with a credit", async () => {
      const p = person();
      as(p);
      await exhaustFreeScans(p);
      await setCredits(p, 20);
      expect((await create(p, site())).status).toBe(201);
      expect((await baselineScansOf(p))[0]?.paidWith).toBe("credit");
      expect(await credits.creditBalance(p.id)).toBe(19);
    });

    it("refuses, and creates nothing, when there are no free scans and no credits", async () => {
      const p = person();
      as(p);
      await exhaustFreeScans(p);
      const res = await create(p, site());
      expect(res.status).toBe(403);
      expect(((await res.json()) as { code: string }).code).toBe("trial_exhausted");
      expect(await subsOf(p)).toHaveLength(0);
      expect(await baselineScansOf(p)).toHaveLength(0);
    });

    it("lets only one of two simultaneous requests ride on the last scan, and charges once", async () => {
      // The last credit is spent by whichever request gets there first; the other is refused without a monitor.
      const p = person();
      as(p);
      await exhaustFreeScans(p);
      await setCredits(p, 1);
      const [a, b] = await Promise.all([create(p, site()), create(p, site())]);
      expect([a.status, b.status].sort()).toEqual([201, 403]);
      expect(await subsOf(p)).toHaveLength(1);
      expect(await credits.creditBalance(p.id)).toBe(0);
    });

    it("does not charge a plan holder for the baseline", async () => {
      const p = person();
      as(p);
      await exhaustFreeScans(p);
      await plan(p, { plan: "unlimited", urlLimit: 5 });
      await setCredits(p, 4);
      expect((await create(p, site())).status).toBe(201);
      expect((await baselineScansOf(p))[0]?.paidWith ?? null).toBeNull();
      expect(await credits.creditBalance(p.id)).toBe(4);
    });
  });

  describe("POST /monitor/subscriptions: finding the scan that was already done", () => {
    it("seeds the card from an earlier scan and says so in the response", async () => {
      // A saved report is stored under the URL the scan ended on (with the slash); the monitor form sends what was
      // typed (without). The lookup used to demand an exact match and found nothing.
      const p = person();
      as(p);
      const typed = site();
      const earlier = await report(p, `${typed}/`, { summary: { grade: "B" } }, 5);
      const res = await create(p, typed);
      expect(res.status).toBe(201);
      const [row] = await subsOf(p);
      expect(row!.lastReportId).toBe(earlier.id);
      expect(row!.lastScanAt).toEqual(earlier.scannedAt);
      expect(((await res.json()) as { seededFrom?: { reportId: string; grade: string } }).seededFrom).toMatchObject({ reportId: earlier.id, grade: "B" });
    });

    it("clean twin: a site that was never scanned is seeded from nothing, and seededFrom is null", async () => {
      const p = person();
      as(p);
      const res = await create(p, site());
      expect(res.status).toBe(201);
      expect((await subsOf(p))[0]!.lastReportId).toBeNull();
      expect(((await res.json()) as { seededFrom: unknown }).seededFrom).toBeNull();
    });

    it("never seeds from another user's scan of the same site", async () => {
      const mine = person();
      const theirs = person();
      const typed = site();
      await report(theirs, `${typed}/`, { summary: { grade: "A" } });
      as(mine);
      const res = await create(mine, typed);
      expect(res.status).toBe(201);
      expect(((await res.json()) as { seededFrom: unknown }).seededFrom).toBeNull();
    });
  });

  describe("/monitor/subscriptions/:id: ownership", () => {
    type R = { method: string; path: string };
    /** Every :id endpoint the router really has, so a route added later is covered without anyone remembering to. */
    function idRoutes(): R[] {
      type Layer = { route?: { path: string; methods: Record<string, boolean> } };
      const out: R[] = [];
      for (const l of (router as unknown as { stack: Layer[] }).stack) {
        if (!l.route || !l.route.path.includes(":id")) continue;
        for (const method of Object.keys(l.route.methods)) out.push({ method: method.toUpperCase(), path: l.route.path });
      }
      return out;
    }
    const urlFor = (r: R, id: string) => r.path.replace(":id", id);

    it("finds the :id endpoints this suite is meant to guard", () => {
      // If this ever reads 0, every test below would pass while asserting nothing.
      expect(idRoutes().length).toBeGreaterThanOrEqual(6);
    });

    it("answers 404, not 403, to a different user on every :id endpoint, and changes nothing", async () => {
      // 404 rather than 403 matters: 403 would confirm the id exists.
      const owner = person();
      const stranger = person();
      const id = await monitorRow(owner, site());
      as(stranger);
      for (const r of idRoutes()) {
        const res = await call(stranger, r.method, urlFor(r, id), r.method === "POST" ? {} : undefined);
        expect(res.status, `${r.method} ${r.path}`).toBe(404);
      }
      const [still] = await subsOf(owner);
      expect(still!.status).toBe("active"); // the stranger's DELETE did not cancel it
    });

    it("refuses an unauthenticated caller on every :id endpoint", async () => {
      const owner = person();
      const id = await monitorRow(owner, site());
      as(null);
      for (const r of idRoutes()) {
        const res = await call(owner, r.method, urlFor(r, id), r.method === "POST" ? {} : undefined);
        expect(res.status, `${r.method} ${r.path}`).toBe(401);
      }
    });

    it("lets the owner read their own subscription's data", async () => {
      const owner = person();
      const id = await monitorRow(owner, site());
      as(owner);
      for (const r of idRoutes().filter((x) => x.method === "GET")) {
        expect((await call(owner, "GET", urlFor(r, id))).status, r.path).toBe(200);
      }
    });
  });

  describe("GET /monitor/subscriptions/:id/history: trend data", () => {
    it("maps vulnCount from the report's real totalVulnerabilities field", async () => {
      // The route used to read `data.summary.vulnCount`, a key that has never existed on a stored report, so every
      // history entry, for every subscription, returned vulnCount: null.
      const p = person();
      as(p);
      const url = site();
      const id = await monitorRow(p, url);
      await report(p, `${url}/`, { summary: { grade: "B", riskScore: 22, totalVulnerabilities: 7 } });
      const body = (await (await call(p, "GET", `/monitor/subscriptions/${id}/history`)).json()) as Array<{ grade: string; vulnCount: number | null }>;
      expect(body[0]?.grade).toBe("B");
      expect(body[0]?.vulnCount).toBe(7);
    });

    it("counts from the list without the scan's notes when the report has one", async () => {
      const p = person();
      as(p);
      const url = site();
      const id = await monitorRow(p, url);
      await report(p, `${url}/`, {
        // Saved before notes were left out of the total: it says 4, the list holds 3 findings and a note.
        summary: { grade: "B", riskScore: 22, totalVulnerabilities: 4 },
        vulnerabilities: [{ category: "a" }, { category: "b" }, { category: "c" }, { category: "Scan Coverage" }],
      });
      const body = (await (await call(p, "GET", `/monitor/subscriptions/${id}/history`)).json()) as Array<{ vulnCount: number | null }>;
      expect(body[0]?.vulnCount).toBe(3);
    });

    it("lists only the caller's own reports for the site, newest first", async () => {
      const p = person();
      const other = person();
      as(p);
      const url = site();
      const id = await monitorRow(p, url);
      const older = await report(p, `${url}/`, { summary: { grade: "C" } }, 6);
      const newer = await report(p, `${url}/`, { summary: { grade: "B" } }, 1);
      await report(other, `${url}/`, { summary: { grade: "F" } }, 0);
      const body = (await (await call(p, "GET", `/monitor/subscriptions/${id}/history`)).json()) as Array<{ id: string }>;
      expect(body.map((r) => r.id)).toEqual([newer.id, older.id]);
    });
  });

  // Last in the file: this stops the job queue for the rest of the process.
  describe("when the baseline scan cannot be queued", () => {
    it("gives the charge back and still creates the monitor", async () => {
      const p = person();
      as(p);
      await exhaustFreeScans(p);
      await setCredits(p, 5);
      const { getBoss } = await import("../lib/queue");
      await (await getBoss()).stop({ graceful: false });
      const res = await create(p, site());
      expect(res.status).toBe(201);
      expect(await subsOf(p)).toHaveLength(1);
      expect(await credits.creditBalance(p.id)).toBe(5); // the credit taken for the baseline came back
    }, 60_000);
  });
});

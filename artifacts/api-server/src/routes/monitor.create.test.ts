import { describe, it, expect, vi, beforeEach } from "vitest";
import { inserted, queuedResults, billingState, makeRes, makeReq, handlerFor, mockFactory1, mockFactory2, mockFactory3, mockFactory4, mockFactory5, mockFactory6, mockFactory7, mockFactory8, mockFactory9, resetState } from "./monitor.testkit";

// Shared mock factories live in monitor.testkit.ts; vi.mock has to be written in the test file itself.
vi.mock("@workspace/db", () => mockFactory1());
vi.mock("drizzle-orm", () => mockFactory2());
vi.mock("../lib/queue", () => mockFactory3());
vi.mock("../lib/logger", () => mockFactory4());
vi.mock("../lib/ssrfGuard", () => mockFactory5());
vi.mock("../lib/rateLimit", () => mockFactory6());
vi.mock("../lib/billing", () => mockFactory7());
vi.mock("../lib/credits", () => mockFactory8());
vi.mock("../lib/freeTrial", () => mockFactory9());

beforeEach(resetState);

describe("POST /monitor/subscriptions — closing the race with the 6-hourly sweep", () => {
  it("sets a future nextScanAt at creation, so the sweep can't read a fresh subscription as already due", async () => {
    // Before this fix, a brand-new subscription had nextScanAt: null and
    // lastScanAt: null until its baseline scan finished — the exact shape
    // isSubscriptionDue() (monitorScheduler.ts) treats as due. A sweep tick
    // landing in that window enqueued a second baseline scan for the same
    // subscription. Asserting the value written here, rather than re-deriving
    // it, is what would catch someone removing the field again.
    // The handler counts the caller's existing subscriptions against their
    // plan limit before creating. COUNT always returns a row in Postgres; the
    // shared mock answers every query with [], so it needs one supplied.
    queuedResults.push([{ value: 0 }]);

    const handle = await handlerFor("post", "/monitor/subscriptions");
    const res = makeRes();
    const before = Date.now();

    await handle(makeReq({ body: { targetUrl: "https://example.com" }, params: {} }), res);

    const subInsert = inserted.find((v) => "targetUrl" in v && "expiresAt" in v);
    expect(subInsert, "no insert into monitor_subscriptions was recorded").toBeDefined();
    expect(subInsert!.nextScanAt).toBeInstanceOf(Date);
    const nextScanAt = subInsert!.nextScanAt as Date;
    // Must be in the future, and specifically past the point a same-day sweep
    // tick could reach — not just "not undefined".
    expect(nextScanAt.getTime()).toBeGreaterThan(before + 24 * 60 * 60 * 1000);
  });
});

describe("POST /monitor/subscriptions — plan limits", () => {
  it("creates without complaint while enforcement is off, however many they already have", async () => {
    // The property that matters on the day this ships: MONITORING_REQUIRES_PLAN
    // is unset in production, so an existing user with any number of monitored
    // sites must be unaffected. A high count here would refuse if the limit
    // were being applied.
    delete process.env["MONITORING_REQUIRES_PLAN"];
    queuedResults.push([{ value: 99 }]);

    const handle = await handlerFor("post", "/monitor/subscriptions");
    const res = makeRes();
    await handle(makeReq({ body: { targetUrl: "https://example.com" }, params: {} }), res);

    expect(res.statusCode).toBe(201);
  });

  it("refuses once the caller is at their plan's URL limit", async () => {
    process.env["MONITORING_REQUIRES_PLAN"] = "true";
    // Billing row lookup, then the count of what they already monitor.
    queuedResults.push([{ plan: "solo", status: "active", urlLimit: 3, grandfathered: false }]);
    queuedResults.push([{ value: 3 }]);

    const handle = await handlerFor("post", "/monitor/subscriptions");
    const res = makeRes();
    await handle(makeReq({ body: { targetUrl: "https://example.com" }, params: {} }), res);

    expect(res.statusCode).toBe(403);
    expect((res.body as { code: string }).code).toBe("monitor_url_limit");
    // Nothing may be created once refused — the check is worthless if the row
    // still lands.
    expect(inserted.find((v) => "targetUrl" in v && "expiresAt" in v)).toBeUndefined();
  });

  it("allows the last slot under the limit", async () => {
    // Guards the boundary: >= vs > is the classic off-by-one here, and getting
    // it wrong sells someone three sites and gives them two.
    process.env["MONITORING_REQUIRES_PLAN"] = "true";
    queuedResults.push([{ plan: "solo", status: "active", urlLimit: 3, grandfathered: false }]);
    queuedResults.push([{ value: 2 }]);

    const handle = await handlerFor("post", "/monitor/subscriptions");
    const res = makeRes();
    await handle(makeReq({ body: { targetUrl: "https://example.com" }, params: {} }), res);

    expect(res.statusCode).toBe(201);
  });

  it("refuses a paused plan before counting anything", async () => {
    process.env["MONITORING_REQUIRES_PLAN"] = "true";
    queuedResults.push([{ plan: "studio", status: "paused", urlLimit: 10, grandfathered: false }]);

    const handle = await handlerFor("post", "/monitor/subscriptions");
    const res = makeRes();
    await handle(makeReq({ body: { targetUrl: "https://example.com" }, params: {} }), res);

    expect(res.statusCode).toBe(403);
    expect((res.body as { code: string }).code).toBe("monitor_plan_required");
    // Says their history survives, because it does — that is the lapse
    // behaviour, and the message is the only place the user learns it.
    expect((res.body as { error: string }).error).toContain("history");
  });
});

describe("POST /monitor/subscriptions — paying for the baseline scan", () => {
  // Adding a monitor runs a full deep scan straight away. Without a plan it is
  // charged like any other scan. It used to demand a free scan specifically,
  // so a customer who had bought credits could not add a single monitor.
  const add = async () => {
    const handle = await handlerFor("post", "/monitor/subscriptions");
    const res = makeRes();
    await handle(makeReq({ body: { targetUrl: "https://example.com" }, params: {} }), res);
    return res;
  };
  const baselineScan = () => inserted.find((v) => v.origin === "monitor" && "tier" in v);

  it("lets a credit holder add a monitor once the free scans are gone, paying with a credit", async () => {
    Object.assign(billingState, { trialExhausted: true, credits: 20, charge: "credit" });
    queuedResults.push([{ value: 0 }]);
    const res = await add();
    expect(res.statusCode).toBe(201);
    expect(baselineScan()?.paidWith).toBe("credit");
  });

  it("refuses, and inserts nothing, when there are no free scans and no credits", async () => {
    Object.assign(billingState, { trialExhausted: true, credits: 0, charge: null });
    const res = await add();
    expect(res.statusCode).toBe(403);
    expect((res.body as { code: string }).code).toBe("trial_exhausted");
    expect(inserted).toHaveLength(0);
  });

  it("refuses without creating the monitor if the last scan was spent by a concurrent request", async () => {
    Object.assign(billingState, { trialExhausted: true, credits: 1, charge: null });
    queuedResults.push([{ value: 0 }]);
    const res = await add();
    expect(res.statusCode).toBe(403);
    expect(inserted.find((v) => "expiresAt" in v)).toBeUndefined();
  });

  it("does not charge a plan holder for the baseline", async () => {
    Object.assign(billingState, { livePlan: true, trialExhausted: true, charge: "credit" });
    queuedResults.push([{ value: 0 }]);
    const res = await add();
    expect(res.statusCode).toBe(201);
    expect(baselineScan()?.paidWith).toBeNull();
  });

  it("gives the charge back when the baseline scan cannot be queued", async () => {
    Object.assign(billingState, { trialExhausted: true, credits: 5, charge: "credit" });
    queuedResults.push([{ value: 0 }]);
    const queue = await import("../lib/queue");
    vi.mocked(queue.enqueueScan).mockRejectedValueOnce(new Error("queue down"));
    const res = await add();
    expect(res.statusCode).toBe(201);
    expect(billingState.refunds).toHaveLength(1);
    expect(billingState.refunds[0]!.kind).toBe("scan");
  });
});

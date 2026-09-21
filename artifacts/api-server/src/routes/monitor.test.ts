import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Every /monitor/subscriptions/:id endpoint takes an id straight from the URL,
 * which is the exact shape of the flaw this product exists to find in other
 * people's applications. Getting it wrong here means one customer reading
 * another's scan history, score trend and regression list.
 *
 * All six currently do it correctly and identically: select scoped by id AND
 * userId, then 404 — which also avoids confirming that somebody else's
 * subscription exists. Nothing was broken when these were written.
 *
 * So these are written structurally rather than one-per-endpoint. The realistic
 * future bug is not someone breaking a handler that works; it is someone adding
 * the seventh endpoint to this file and scoping the lookup by id alone. A test
 * that enumerates the router and holds every :id route to the rule catches that
 * on the day it is written. A set of per-endpoint tests would pass, because the
 * new endpoint would not be in them.
 */

/** Every `where(...)` clause the route handlers built, in order. */
const wheres: unknown[] = [];
/** Every `values(...)` object passed to an insert, in order. */
const inserted: Record<string, unknown>[] = [];
/** Canned rows to hand back to successive awaited queries, in call order. */
const queuedResults: unknown[][] = [];

type Eq = { op: "eq"; col: unknown; val: unknown };

/** Flattens the nested and()/eq() structure the drizzle mock records. */
function eqsIn(clause: unknown): Eq[] {
  if (!clause || typeof clause !== "object") return [];
  // Read as an open shape rather than `And & Eq` — that intersection collapses
  // to never, since the two `op` literals cannot both hold.
  const node = clause as { op?: string; args?: unknown[] };
  if (node.op === "eq") return [clause as Eq];
  if (node.op === "and") return (node.args ?? []).flatMap(eqsIn);
  return [];
}

vi.mock("@workspace/db", () => {
  // Resolves at every point drizzle can terminate a chain, so a handler can
  // await after where(), orderBy(), limit() or offset() without the mock
  // needing to know which shape each route uses.
  const chain: Record<string, unknown> = {};
  const self = () => chain;
  let pendingReturning = false;
  let lastValues: Record<string, unknown> | null = null;
  let idCounter = 0;
  Object.assign(chain, {
    select: self,
    from: self,
    where: (w: unknown) => {
      wheres.push(w);
      return chain;
    },
    orderBy: self,
    limit: self,
    offset: self,
    innerJoin: self,
    leftJoin: self,
    groupBy: self,
    set: self,
    values: (v: Record<string, unknown>) => {
      inserted.push(v);
      lastValues = v;
      return chain;
    },
    returning: () => {
      pendingReturning = true;
      return chain;
    },
    then: (resolve: (v: unknown) => unknown) => {
      // A test-supplied row wins over the generic fallbacks below, for
      // handlers that make more than one sequential query and need each
      // one to answer differently (e.g. "found the subscription" then
      // "here are its reports").
      if (queuedResults.length > 0) {
        resolve(queuedResults.shift());
        return;
      }
      if (pendingReturning) {
        pendingReturning = false;
        resolve([{ id: `mock-id-${++idCounter}`, ...lastValues }]);
        return;
      }
      resolve([]);
    },
  });
  const table = (name: string) =>
    new Proxy({}, { get: (_t, prop) => `${name}.${String(prop)}` });
  return {
    db: { select: self, insert: self, update: self, delete: self },
    monitorSubscriptionsTable: table("monitor_subscriptions"),
    cveAlertsTable: table("cve_alerts"),
    reportsTable: table("reports"),
    monitorScoreHistoryTable: table("monitor_score_history"),
    monitorRegressionsTable: table("monitor_regressions"),
    certExpiryAlertsTable: table("cert_expiry_alerts"),
    scansTable: table("scans"),
  };
});

vi.mock("drizzle-orm", () => ({
  eq: (col: unknown, val: unknown) => ({ op: "eq", col, val }),
  and: (...args: unknown[]) => ({ op: "and", args }),
  desc: (c: unknown) => c,
  count: () => ({ op: "count" }),
  sql: Object.assign(() => ({ op: "sql" }), { raw: () => ({ op: "sql" }) }),
}));

vi.mock("../lib/queue", () => ({ enqueueScan: vi.fn(async () => undefined) }));
vi.mock("../lib/logger", () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
  },
}));
vi.mock("../lib/ssrfGuard", () => ({ checkScanTarget: async () => ({ ok: true }) }));
vi.mock("../lib/rateLimit", () => ({
  rateLimitMiddleware: () => (_req: unknown, _res: unknown, next: () => void) => next(),
  scanRateLimitRules: () => [],
}));
vi.mock("../lib/freeTrial", () => ({
  trialScansExhausted: async () => false,
  TRIAL_LIMIT_MESSAGE: "out of scans",
  TRIAL_LIMIT_CODE: "trial_exhausted",
}));

interface RouteLayer {
  route?: { path: string; methods: Record<string, boolean>; stack: { handle: Handler }[] };
}
type Handler = (req: unknown, res: unknown, next?: unknown) => Promise<void> | void;

function makeRes() {
  const res: Record<string, unknown> & { statusCode: number; body: unknown } = {
    statusCode: 200,
    body: null,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

function makeReq(overrides: Record<string, unknown> = {}) {
  return {
    params: { id: "sub-belonging-to-someone-else" },
    body: {},
    query: {},
    isAuthenticated: () => true,
    user: { id: "user-1", email: "owner@example.com" },
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    ...overrides,
  };
}

/** Every :id route on the monitor router, with its terminal handler. */
async function idRoutes(): Promise<Array<{ label: string; handle: Handler }>> {
  const mod = await import("./monitor.js");
  const router = mod.default as unknown as { stack: RouteLayer[] };
  return router.stack
    .filter((l): l is Required<RouteLayer> => !!l.route?.path.includes("/:id"))
    .map((l) => {
      const method = Object.keys(l.route.methods)[0]!.toUpperCase();
      return {
        label: `${method} ${l.route.path}`,
        // The last handler in the stack is the route's own, after any middleware.
        handle: l.route.stack[l.route.stack.length - 1]!.handle,
      };
    });
}

beforeEach(() => {
  wheres.length = 0;
  inserted.length = 0;
  queuedResults.length = 0;
  vi.resetModules();
});

/** The terminal handler for one exact method+path, for routes idRoutes() won't match. */
async function handlerFor(method: string, path: string): Promise<Handler> {
  const mod = await import("./monitor.js");
  const router = mod.default as unknown as { stack: RouteLayer[] };
  const layer = router.stack.find(
    (l) => l.route?.path === path && l.route.methods[method],
  );
  if (!layer?.route) throw new Error(`no ${method} ${path} route`);
  return layer.route.stack[layer.route.stack.length - 1]!.handle;
}

describe("/monitor/subscriptions/:id — ownership", () => {
  it("finds the :id endpoints this file is meant to guard", async () => {
    // If this ever reads 0, every test below would pass while asserting
    // nothing — the failure mode that makes structural tests worthless.
    const routes = await idRoutes();
    expect(routes.length).toBeGreaterThanOrEqual(6);
  });

  it("scopes every subscription lookup by the caller's own user id", async () => {
    for (const { label, handle } of await idRoutes()) {
      wheres.length = 0;
      await handle(makeReq(), makeRes());

      // The first lookup a handler makes is the subscription itself. It must
      // constrain BOTH the id from the URL and the caller — an id-only lookup
      // is the IDOR.
      const first = eqsIn(wheres[0]);
      const byId = first.some((e) => String(e.col).endsWith(".id"));
      const byOwner = first.some(
        (e) => String(e.col).endsWith(".userId") && e.val === "user-1",
      );

      expect(byId, `${label} must constrain the subscription id`).toBe(true);
      expect(byOwner, `${label} must constrain userId to the caller`).toBe(true);
    }
  });

  it("answers 404, not 403, when the subscription is not the caller's", async () => {
    // The mock resolves every query to [], which is what a scoped lookup
    // returns for someone else's subscription. 404 rather than 403 matters:
    // 403 would confirm the id exists.
    for (const { label, handle } of await idRoutes()) {
      const res = makeRes();
      await handle(makeReq(), res);
      expect(res.statusCode, label).toBe(404);
    }
  });

  it("refuses an unauthenticated caller before touching the database", async () => {
    for (const { label, handle } of await idRoutes()) {
      wheres.length = 0;
      const res = makeRes();
      await handle(makeReq({ isAuthenticated: () => false, user: undefined }), res);

      expect(res.statusCode, label).toBe(401);
      // Auth first, so an anonymous caller cannot spend queries — or, on the
      // rescan endpoint, a real user's scan budget.
      expect(wheres, `${label} queried the db while unauthenticated`).toHaveLength(0);
    }
  });
});

describe("POST /monitor/subscriptions — closing the race with the 6-hourly sweep", () => {
  it("sets a future nextScanAt at creation, so the sweep can't read a fresh subscription as already due", async () => {
    // Before this fix, a brand-new subscription had nextScanAt: null and
    // lastScanAt: null until its baseline scan finished — the exact shape
    // isSubscriptionDue() (monitorScheduler.ts) treats as due. A sweep tick
    // landing in that window enqueued a second baseline scan for the same
    // subscription. Asserting the value written here, rather than re-deriving
    // it, is what would catch someone removing the field again.
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

describe("GET /monitor/subscriptions/:id/history — trend data", () => {
  it("maps vulnCount from the report's real totalVulnerabilities field", async () => {
    // The route used to read `data.summary.vulnCount`, a key that has never
    // existed on a stored report (worker.ts writes `totalVulnerabilities`) —
    // every history entry, for every subscription, returned vulnCount: null.
    queuedResults.push([{ id: "sub-1" }]); // ownership lookup
    queuedResults.push([
      {
        id: "report-1",
        scanId: "scan-1",
        scannedAt: new Date("2026-09-01T00:00:00.000Z"),
        tier: "deep",
        data: { summary: { grade: "B", riskScore: 22, totalVulnerabilities: 7 } },
      },
    ]); // the reports query

    const routes = await idRoutes();
    const history = routes.find((r) => r.label.includes("/history"));
    expect(history, "no GET .../history route found").toBeDefined();

    const res = makeRes();
    await history!.handle(makeReq(), res);

    const body = res.body as Array<{ vulnCount: number | null; grade: string | null }>;
    expect(body[0]?.grade).toBe("B");
    expect(body[0]?.vulnCount).toBe(7);
  });
});

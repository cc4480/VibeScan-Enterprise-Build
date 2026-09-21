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
    values: self,
    returning: self,
    then: (resolve: (v: unknown) => unknown) => resolve([]),
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
  logger: { child: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() }) },
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
  vi.resetModules();
});

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

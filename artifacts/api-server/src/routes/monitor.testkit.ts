import { it, vi, beforeEach } from "vitest";

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
export const wheres: unknown[] = [];

/** Every `values(...)` object passed to an insert, in order. */
export const inserted: Record<string, unknown>[] = [];

/** Canned rows to hand back to successive awaited queries, in call order. */
export const queuedResults: unknown[][] = [];

export type Eq = { op: "eq"; col: unknown; val: unknown };

/** Flattens the nested and()/eq() structure the drizzle mock records. */
export function eqsIn(clause: unknown): Eq[] {
  if (!clause || typeof clause !== "object") return [];
  // Read as an open shape rather than `And & Eq` — that intersection collapses
  // to never, since the two `op` literals cannot both hold.
  const node = clause as { op?: string; args?: unknown[] };
  if (node.op === "eq") return [clause as Eq];
  if (node.op === "and") return (node.args ?? []).flatMap(eqsIn);
  return [];
}

// Plan and charging decisions are billing.ts's (tested against a real database
// in billing.integration.test.ts). Here they are set per test, so the queued
// database answers below line up with the route's own queries.
export const billingState = {
  livePlan: false,
  charge: "free" as string | null,
  trialExhausted: false,
  credits: 0,
  refunds: [] as Array<{ kind: "charge"; paidWith: string | null } | { kind: "scan"; scanId: string }>,
};

export interface RouteLayer {
  route?: { path: string; methods: Record<string, boolean>; stack: { handle: Handler }[] };
}

export type Handler = (req: unknown, res: unknown, next?: unknown) => Promise<void> | void;

export function makeRes() {
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

export function makeReq(overrides: Record<string, unknown> = {}) {
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
export async function idRoutes(): Promise<Array<{ label: string; handle: Handler }>> {
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

/** The terminal handler for one exact method+path, for routes idRoutes() won't match. */
export async function handlerFor(method: string, path: string): Promise<Handler> {
  const mod = await import("./monitor.js");
  const router = mod.default as unknown as { stack: RouteLayer[] };
  const layer = router.stack.find(
    (l) => l.route?.path === path && l.route.methods[method],
  );
  if (!layer?.route) throw new Error(`no ${method} ${path} route`);
  return layer.route.stack[layer.route.stack.length - 1]!.handle;
}

/** Factory for vi.mock("@workspace/db"). */
export const mockFactory1 = () => {
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
    // Omitting this is not a harmless gap: entitlements.ts fails OPEN on a
    // database error, so an undefined table here throws, the catch allows the
    // request, and every plan-limit test silently passes for the wrong reason.
    billingSubscriptionsTable: table("billing_subscriptions"),
  };
};

/** Factory for vi.mock("drizzle-orm"). */
export const mockFactory2 = () => ({
  eq: (col: unknown, val: unknown) => ({ op: "eq", col, val }),
  and: (...args: unknown[]) => ({ op: "and", args }),
  desc: (c: unknown) => c,
  count: () => ({ op: "count" }),
  sql: Object.assign(() => ({ op: "sql" }), { raw: () => ({ op: "sql" }) }),
});

/** Factory for vi.mock("../lib/queue"). */
export const mockFactory3 = () => ({ enqueueScan: vi.fn(async () => undefined) });

/** Factory for vi.mock("../lib/logger"). */
export const mockFactory4 = () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn() }),
  },
});

/** Factory for vi.mock("../lib/ssrfGuard"). */
export const mockFactory5 = () => ({ checkScanTarget: async () => ({ ok: true }) });

/** Factory for vi.mock("../lib/rateLimit"). */
export const mockFactory6 = () => ({
  rateLimitMiddleware: () => (_req: unknown, _res: unknown, next: () => void) => next(),
  scanRateLimitRules: () => [],
});

/** Factory for vi.mock("../lib/billing"). */
export const mockFactory7 = () => ({
  hasLivePlan: async () => billingState.livePlan,
  chargeScan: async () => billingState.charge,
  refundCharge: async (_u: string, paidWith: string | null) => {
    billingState.refunds.push({ kind: "charge", paidWith });
  },
  refundFailedScan: async (scanId: string) => {
    billingState.refunds.push({ kind: "scan", scanId });
    return null;
  },
});

/** Factory for vi.mock("../lib/credits"). */
export const mockFactory8 = () => ({ creditBalance: async () => billingState.credits });

/** Factory for vi.mock("../lib/freeTrial"). */
export const mockFactory9 = () => ({
  trialScansExhausted: async () => billingState.trialExhausted,
  insertScanRow: async (values: Record<string, unknown>) => {
    inserted.push(values);
    return { id: "mock-scan-id", ...values };
  },
  TrialExhaustedError: class TrialExhaustedError extends Error {},
  TRIAL_LIMIT_MESSAGE: "out of scans",
  TRIAL_LIMIT_CODE: "trial_exhausted",
});

/** The beforeEach every test file registers: resets the recorded state and the module registry. */
export const resetState = () => {
  wheres.length = 0;
  inserted.length = 0;
  queuedResults.length = 0;
  // Reset rather than leave set: a test that turns enforcement on would
  // otherwise silently change the behaviour of every test after it, and the
  // default-off case is the one that matters most right now.
  delete process.env["MONITORING_REQUIRES_PLAN"];
  Object.assign(billingState, { livePlan: false, charge: "free", trialExhausted: false, credits: 0, refunds: [] });
  vi.resetModules();
};

import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Preferences are stored as opt-OUTs and presented as opt-INs, because the
 * default for every flag is "send it" and a false default is what survives a
 * new column being added. That inversion happens once, in the route — so a
 * bug here flips the meaning of every toggle at once, and the user's setting
 * would then mean the opposite of what they chose, silently.
 */

const updated: Record<string, unknown>[] = [];
const queued: unknown[][] = [];

vi.mock("@workspace/db", () => {
  const chain: Record<string, unknown> = {};
  const self = () => chain;
  Object.assign(chain, {
    select: self,
    from: self,
    where: self,
    limit: self,
    set: (v: Record<string, unknown>) => {
      updated.push(v);
      return chain;
    },
    returning: self,
    then: (resolve: (v: unknown) => unknown) =>
      resolve(queued.length > 0 ? queued.shift() : []),
  });
  const table = (name: string) =>
    new Proxy({}, { get: (_t, prop) => `${name}.${String(prop)}` });
  return { db: { select: self, update: self }, usersTable: table("users") };
});

vi.mock("drizzle-orm", () => ({ eq: (c: unknown, v: unknown) => ({ c, v }) }));
vi.mock("../lib/emailPrefs", () => ({ verifyUnsubscribeToken: () => null }));
vi.mock("../lib/mailer", () => ({ setMarketingSubscription: vi.fn(async () => undefined) }));

interface RouteLayer {
  route?: { path: string; methods: Record<string, boolean>; stack: { handle: Handler }[] };
}
type Handler = (req: unknown, res: unknown) => Promise<void> | void;

async function handlerFor(method: "get" | "put", path: string): Promise<Handler> {
  const mod = await import("./emailPreferences.js");
  const router = mod.default as unknown as { stack: RouteLayer[] };
  const layer = router.stack.find((l) => l.route?.path === path && l.route.methods[method]);
  if (!layer?.route) throw new Error(`no ${method} ${path}`);
  return layer.route.stack[layer.route.stack.length - 1]!.handle;
}

function makeRes() {
  const res: Record<string, unknown> & { statusCode: number; body: any } = {
    statusCode: 200,
    body: null,
    status(code: number) { res.statusCode = code; return res; },
    json(payload: unknown) { res.body = payload; return res; },
  };
  return res;
}

const makeReq = (body: unknown = {}) => ({
  body,
  isAuthenticated: () => true,
  user: { id: "user-1" },
  log: { error: vi.fn(), info: vi.fn() },
});

beforeEach(() => {
  updated.length = 0;
  queued.length = 0;
  vi.resetModules();
});

describe("GET /account/email-preferences", () => {
  it("presents stored opt-outs as opt-ins", async () => {
    queued.push([{
      marketingOptedOut: true,
      alertEmailsOptedOut: false,
      cve: false,
      regression: true,
      certExpiry: false,
      scanComplete: false,
      minSeverity: "high",
    }]);

    const res = makeRes();
    await (await handlerFor("get", "/account/email-preferences"))(makeReq(), res);

    expect(res.body.productUpdates).toBe(false);   // opted OUT of marketing
    expect(res.body.monitorAlerts).toBe(true);
    expect(res.body.alerts.cve).toBe(true);
    expect(res.body.alerts.regression).toBe(false); // opted OUT of regressions
    expect(res.body.minSeverity).toBe("high");
  });

  it("defaults a user with no row to everything on, no floor", async () => {
    // Today's behaviour for anyone who has never touched a setting.
    const res = makeRes();
    await (await handlerFor("get", "/account/email-preferences"))(makeReq(), res);

    expect(res.body.monitorAlerts).toBe(true);
    // Exhaustive on purpose. A new alert kind added without a default of
    // "send it" would change what existing users receive without anyone
    // choosing that, and this assertion is what makes the omission fail.
    expect(res.body.alerts).toEqual({
      cve: true, regression: true, certExpiry: true, scanComplete: true,
      availability: true, drift: true,
    });
    expect(res.body.minSeverity).toBe("info");
  });
});

describe("PUT /account/email-preferences", () => {
  it("stores the inverse of what the user asked to receive", async () => {
    queued.push([{}]);
    const res = makeRes();
    await (await handlerFor("put", "/account/email-preferences"))(
      makeReq({ alerts: { scanComplete: false } }),
      res,
    );

    // Asked NOT to receive scan_complete, so the opt-out column goes true.
    expect(updated[0]).toMatchObject({ notifyScanCompleteOptedOut: true });
  });

  it("stores the two pulse-check toggles in their own columns", async () => {
    // The lesson from the last round: a toggle that animates and stores nothing
    // is invisible to the compiler and to every other test here, because the
    // column name is a string in an untyped update object. These two are new,
    // so they get the check the older four earned the hard way.
    queued.push([{}]);
    await (await handlerFor("put", "/account/email-preferences"))(
      makeReq({ alerts: { availability: false } }),
      makeRes(),
    );
    expect(Object.keys(updated[0]!)).toEqual(["notifyAvailabilityOptedOut"]);

    queued.push([{}]);
    await (await handlerFor("put", "/account/email-preferences"))(
      makeReq({ alerts: { drift: false } }),
      makeRes(),
    );
    expect(Object.keys(updated[1]!)).toEqual(["notifyDriftOptedOut"]);
  });

  it("changes only the fields supplied", async () => {
    // A settings screen sends one toggle at a time. Writing defaults for the
    // others would silently reset preferences the user never touched.
    queued.push([{}]);
    const res = makeRes();
    await (await handlerFor("put", "/account/email-preferences"))(
      makeReq({ alerts: { cve: false } }),
      res,
    );

    expect(Object.keys(updated[0]!)).toEqual(["notifyCveOptedOut"]);
  });

  it("accepts a valid severity floor", async () => {
    queued.push([{}]);
    const res = makeRes();
    await (await handlerFor("put", "/account/email-preferences"))(
      makeReq({ minSeverity: "medium" }),
      res,
    );

    expect(res.statusCode).toBe(200);
    expect(updated[0]).toMatchObject({ notifyMinSeverity: "medium" });
  });

  it("REFUSES an unrecognised severity rather than storing it", async () => {
    // Coercing junk to a default would quietly decide which security alerts
    // somebody stops receiving, and nothing would report that it happened.
    const res = makeRes();
    await (await handlerFor("put", "/account/email-preferences"))(
      makeReq({ minSeverity: "urgent" }),
      res,
    );

    expect(res.statusCode).toBe(400);
    expect(updated).toHaveLength(0);
  });

  it("refuses a body with nothing to change", async () => {
    const res = makeRes();
    await (await handlerFor("put", "/account/email-preferences"))(makeReq({}), res);

    expect(res.statusCode).toBe(400);
    expect(updated).toHaveLength(0);
  });

  it("refuses an unauthenticated caller before touching anything", async () => {
    const res = makeRes();
    const req = { ...makeReq({ minSeverity: "high" }), isAuthenticated: () => false };
    await (await handlerFor("put", "/account/email-preferences"))(req, res);

    expect(res.statusCode).toBe(401);
    expect(updated).toHaveLength(0);
  });
});

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * What the verification endpoints say about expiry, and that a lapsed row can
 * be verified again. The gate's own date logic is in activeProbeGate.test.ts and
 * the integration test; this is the client-facing side: `verified` must mean
 * "valid now", not "once passed", or the page would show a green tick for a
 * domain the scanner has already stopped probing.
 */

const DAY = 86_400_000;
const NOW = new Date("2026-10-05T12:00:00.000Z");

type Row = {
  id: string;
  userId: string;
  domain: string;
  token: string;
  method: "dns" | "well_known" | null;
  verifiedAt: Date | null;
  lastCheckedAt: Date | null;
  createdAt: Date;
};

const state = { rows: [] as Row[], updates: [] as Record<string, unknown>[] };

vi.mock("@workspace/db", () => {
  const selectChain: any = {
    from: () => selectChain,
    where: () => selectChain,
    orderBy: () => Promise.resolve(state.rows),
    then: (resolve: (v: unknown) => unknown) => resolve(state.rows.slice(0, 1)),
  };
  return {
    db: {
      select: () => selectChain,
      update: () => ({
        set: (v: Record<string, unknown>) => {
          state.updates.push(v);
          return { where: () => ({ returning: () => Promise.resolve([{ ...state.rows[0], ...v }]) }) };
        },
      }),
    },
    domainVerificationsTable: {},
  };
});
vi.mock("drizzle-orm", () => ({ and: () => ({}), eq: () => ({}), desc: () => ({}) }));
vi.mock("./accountShared", () => ({ isRateLimited: () => false }));

const check = vi.fn();
vi.mock("../lib/domainVerify", async (orig) => ({
  ...(await orig<typeof import("../lib/domainVerify")>()),
  runVerificationCheck: (...a: unknown[]) => check(...a),
}));

type Handler = (req: any, res: any) => Promise<void>;
async function handler(method: "get" | "post", path: string): Promise<Handler> {
  const mod = await import("./domainVerification.js");
  const router = mod.default as unknown as {
    stack: { route?: { path: string; methods: Record<string, boolean>; stack: { handle: Handler }[] } }[];
  };
  const layer = router.stack.find((l) => l.route?.path === path && l.route.methods[method])!;
  return layer.route!.stack[0]!.handle;
}

function call(h: Handler, req: Record<string, unknown> = {}) {
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    let status = 200;
    const res = {
      status(c: number) {
        status = c;
        return res;
      },
      json(b: unknown) {
        resolve({ status, body: b });
      },
    };
    h(
      {
        isAuthenticated: () => true,
        user: { id: "user-1" },
        log: { error: vi.fn(), info: vi.fn() },
        params: { domain: "example.com" },
        ...req,
      },
      res,
    ).catch(reject);
  });
}

const row = (verifiedAt: Date | null): Row => ({
  id: "v1",
  userId: "user-1",
  domain: "example.com",
  token: "secscan-verify-abc",
  method: verifiedAt ? "dns" : null,
  verifiedAt,
  lastCheckedAt: verifiedAt,
  createdAt: new Date(NOW.getTime() - 60 * DAY),
});

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  state.rows = [];
  state.updates = [];
  check.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("GET /domain-verifications", () => {
  it("reports a recent verification as verified, with the date it lapses", async () => {
    const verifiedAt = new Date(NOW.getTime() - 3 * DAY);
    state.rows = [row(verifiedAt)];

    const { body } = await call(await handler("get", "/domain-verifications"));

    const v = body.verifications[0];
    expect(v.verified).toBe(true);
    expect(v.verifiedAt).toEqual(verifiedAt);
    expect(v.expiresAt).toEqual(new Date(verifiedAt.getTime() + 14 * DAY));
  });

  it("reports a lapsed verification as not verified, still carrying the token to republish", async () => {
    const verifiedAt = new Date(NOW.getTime() - 20 * DAY);
    state.rows = [row(verifiedAt)];

    const { body } = await call(await handler("get", "/domain-verifications"));

    const v = body.verifications[0];
    expect(v.verified).toBe(false);
    expect(v.expiresAt).toEqual(new Date(verifiedAt.getTime() + 14 * DAY)); // in the past
    expect(v.token).toBe("secscan-verify-abc");
  });

  it("draws the line at exactly 14 days, the same side the gate's SQL does", async () => {
    state.rows = [row(new Date(NOW.getTime() - 14 * DAY))];
    const { body } = await call(await handler("get", "/domain-verifications"));
    expect(body.verifications[0].verified).toBe(false);
  });

  it("reports a never-verified row with no dates", async () => {
    state.rows = [row(null)];
    const { body } = await call(await handler("get", "/domain-verifications"));
    expect(body.verifications[0]).toMatchObject({ verified: false, verifiedAt: null, expiresAt: null });
  });
});

describe("POST /domain-verifications/:domain/check", () => {
  const path = "/domain-verifications/:domain/check";

  it("sets verifiedAt to now when a user passes the check", async () => {
    state.rows = [row(null)];
    check.mockResolvedValue("well_known");

    const { status, body } = await call(await handler("post", path));

    expect(status).toBe(200);
    expect(check).toHaveBeenCalledWith("example.com", "secscan-verify-abc");
    expect(state.updates[0]).toMatchObject({ verifiedAt: NOW, lastCheckedAt: NOW, method: "well_known" });
    expect(body.verification.verified).toBe(true);
    expect(body.verification.expiresAt).toEqual(new Date(NOW.getTime() + 14 * DAY));
  });

  it("re-runs the check for a lapsed row, and verifies it again on a pass", async () => {
    state.rows = [row(new Date(NOW.getTime() - 20 * DAY))];
    check.mockResolvedValue("dns");

    const { status, body } = await call(await handler("post", path));

    expect(check).toHaveBeenCalledTimes(1);
    expect(status).toBe(200);
    expect(state.updates[0]).toMatchObject({ verifiedAt: NOW, method: "dns" });
    expect(body.verification.verified).toBe(true);
  });

  it("answers 409 for a lapsed row whose proof is still missing, and does not move verifiedAt", async () => {
    state.rows = [row(new Date(NOW.getTime() - 20 * DAY))];
    check.mockResolvedValue(null);

    const { status, body } = await call(await handler("post", path));

    expect(status).toBe(409);
    expect(state.updates[0]).not.toHaveProperty("verifiedAt");
    expect(body.verification.verified).toBe(false);
  });

  it("answers a still-valid verification without running another check", async () => {
    state.rows = [row(new Date(NOW.getTime() - 2 * DAY))];

    const { status, body } = await call(await handler("post", path));

    expect(status).toBe(200);
    expect(check).not.toHaveBeenCalled();
    expect(state.updates).toHaveLength(0);
    expect(body.verification.verified).toBe(true);
  });
});

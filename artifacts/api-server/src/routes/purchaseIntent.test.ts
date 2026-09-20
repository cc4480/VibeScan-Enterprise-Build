import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The cap is currently a wall with nothing behind it, and this route is the
 * only thing that notices somebody walked into it wanting to pay. So the two
 * failures that matter are losing the signal (an error the caller swallows)
 * and inflating it (one impatient person counted twice).
 */

const state: {
  inserted: unknown[];
  conflictTarget: unknown;
  selectRows: unknown[];
  insertThrows: Error | null;
} = { inserted: [], conflictTarget: null, selectRows: [], insertThrows: null };

vi.mock("@workspace/db", () => {
  const selectChain = {
    from: () => selectChain,
    where: () => selectChain,
    limit: () => Promise.resolve(state.selectRows),
  };
  // Drizzle only resolves at the END of the chain, so a failure has to surface
  // from onConflictDoNothing. Rejecting from values() instead left a rejected
  // promise nobody awaited and made the chain blow up on the wrong call.
  const insertChain = {
    values: (v: unknown) => {
      if (!state.insertThrows) state.inserted.push(v);
      return {
        onConflictDoNothing: (opts: unknown) => {
          state.conflictTarget = opts;
          return state.insertThrows
            ? Promise.reject(state.insertThrows)
            : Promise.resolve(undefined);
        },
      };
    },
  };
  return {
    db: { select: () => selectChain, insert: () => insertChain },
    purchaseIntentsTable: { userId: "user_id", createdAt: "created_at" },
    scansTable: { userId: "user_id", origin: "origin" },
  };
});

vi.mock("drizzle-orm", () => ({
  eq: (col: unknown, val: unknown) => ({ op: "eq", col, val }),
  and: (...a: unknown[]) => ({ op: "and", args: a }),
  count: () => ({ op: "count" }),
}));

vi.mock("../lib/freeTrial", () => ({
  trialScansUsedBy: async () => 5,
  FREE_TRIAL_SCAN_LIMIT: 5,
}));

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
    isAuthenticated: () => true,
    user: { id: "user-1", email: "someone@example.com" },
    log: { error: vi.fn(), info: vi.fn() },
    ...overrides,
  };
}

/** Pulls one handler off the router's stack by method and path. */
async function handlerFor(method: "get" | "post") {
  const mod = await import("./purchaseIntent.js");
  const router = mod.default as unknown as {
    stack: { route?: { path: string; methods: Record<string, boolean>; stack: { handle: unknown }[] } }[];
  };
  const layer = router.stack.find(
    (l) => l.route?.path === "/purchase-intent" && l.route.methods[method],
  );
  if (!layer?.route) throw new Error(`no ${method} /purchase-intent route`);
  return layer.route.stack[0]!.handle as (req: unknown, res: unknown) => Promise<void>;
}

beforeEach(() => {
  state.inserted = [];
  state.conflictTarget = null;
  state.selectRows = [];
  state.insertThrows = null;
});

describe("POST /purchase-intent", () => {
  it("records the signal with the address we would actually mail", async () => {
    const handle = await handlerFor("post");
    const res = makeRes();
    await handle(makeReq(), res);

    expect(res.statusCode).toBe(201);
    expect(state.inserted).toEqual([{ userId: "user-1", email: "someone@example.com" }]);
  });

  it("counts one person once, however many times they press the button", async () => {
    const handle = await handlerFor("post");
    for (let i = 0; i < 3; i++) await handle(makeReq(), makeRes());

    // The insert is guarded by the unique user_id, not by the client behaving.
    expect(state.conflictTarget).toEqual({ target: "user_id" });
  });

  it("refuses an account with no address, rather than banking an unreachable signal", async () => {
    const handle = await handlerFor("post");
    const res = makeRes();
    await handle(makeReq({ user: { id: "user-1", email: null } }), res);

    expect(res.statusCode).toBe(400);
    expect(state.inserted).toHaveLength(0);
  });

  it("requires a session", async () => {
    const handle = await handlerFor("post");
    const res = makeRes();
    await handle(makeReq({ isAuthenticated: () => false }), res);

    expect(res.statusCode).toBe(401);
    expect(state.inserted).toHaveLength(0);
  });

  it("reports a write failure instead of claiming success", async () => {
    // Telling someone they are on the list when the row never landed is the
    // one outcome that loses the signal silently.
    state.insertThrows = new Error("connection reset");
    const handle = await handlerFor("post");
    const res = makeRes();
    await handle(makeReq(), res);

    expect(res.statusCode).toBe(500);
  });
});

describe("GET /purchase-intent", () => {
  it("says not-registered when there is no row", async () => {
    const handle = await handlerFor("get");
    const res = makeRes();
    await handle(makeReq(), res);

    expect(res.body).toMatchObject({ registered: false, scansUsed: 5, scanLimit: 5 });
  });

  it("says registered once a row exists", async () => {
    state.selectRows = [{ createdAt: new Date() }];
    const handle = await handlerFor("get");
    const res = makeRes();
    await handle(makeReq(), res);

    expect(res.body).toMatchObject({ registered: true });
  });
});

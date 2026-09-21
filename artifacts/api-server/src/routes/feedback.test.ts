import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The free-scan cap exists to get people testing the scanner and saying what
 * happened, and this route is the only thing that catches what they say. So the
 * failures that matter are losing a submission, and refusing one from someone
 * who never signed in — the whole point being that account creation is not the
 * price of being heard.
 *
 * Shipped 2026-09-20 on a single manual POST against production, which is
 * exactly the standard this repo's test report exists to distrust.
 */

const state: { inserted: unknown[]; insertThrows: Error | null } = {
  inserted: [],
  insertThrows: null,
};

vi.mock("@workspace/db", () => {
  const insertChain = {
    values: (v: unknown) => {
      if (state.insertThrows) return Promise.reject(state.insertThrows);
      state.inserted.push(v);
      return Promise.resolve(undefined);
    },
  };
  return {
    db: { insert: () => insertChain },
    feedbackTable: { id: "id", userId: "user_id" },
  };
});

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

function makeReq(body: unknown, overrides: Record<string, unknown> = {}) {
  return {
    body,
    isAuthenticated: () => false,
    log: { error: vi.fn(), info: vi.fn() },
    ...overrides,
  };
}

const signedIn = {
  isAuthenticated: () => true,
  user: { id: "user-1", email: "someone@example.com" },
};

async function handler() {
  const mod = await import("./feedback.js");
  const router = mod.default as unknown as {
    stack: { route?: { path: string; methods: Record<string, boolean>; stack: { handle: unknown }[] } }[];
  };
  const layer = router.stack.find((l) => l.route?.path === "/feedback" && l.route.methods["post"]);
  if (!layer?.route) throw new Error("no post /feedback route");
  return layer.route.stack[0]!.handle as (req: unknown, res: unknown) => Promise<void>;
}

beforeEach(() => {
  state.inserted = [];
  state.insertThrows = null;
  vi.resetModules();
});

describe("POST /feedback — who may submit", () => {
  it("accepts a submission from someone who is not signed in", () => {
    // The reason userId is nullable. An anonymous scan is still a real user
    // with a real opinion, and requiring an account here would silently filter
    // the feedback down to people who already committed to the product.
    return handler().then(async (h) => {
      const res = makeRes();
      await h(makeReq({ message: "the report was clearer than I expected" }), res);

      expect(res.statusCode).toBe(201);
      expect(res.body).toEqual({ recorded: true });
      expect(state.inserted).toHaveLength(1);
      expect(state.inserted[0]).toMatchObject({ userId: null, email: null });
    });
  });

  it("attaches the account when the submitter is signed in", async () => {
    const h = await handler();
    const res = makeRes();
    await h(makeReq({ message: "found a false positive on my staging box" }, signedIn), res);

    expect(res.statusCode).toBe(201);
    expect(state.inserted[0]).toMatchObject({
      userId: "user-1",
      email: "someone@example.com",
    });
  });
});

describe("POST /feedback — what it refuses", () => {
  it("refuses an empty message", async () => {
    const h = await handler();
    const res = makeRes();
    await h(makeReq({ message: "" }), res);

    expect(res.statusCode).toBe(400);
    expect(state.inserted).toHaveLength(0);
  });

  it("refuses a message that is only whitespace", async () => {
    const h = await handler();
    const res = makeRes();
    await h(makeReq({ message: "   \n\t  " }), res);

    expect(res.statusCode).toBe(400);
    expect(state.inserted).toHaveLength(0);
  });

  it("refuses a missing body without throwing", async () => {
    const h = await handler();
    const res = makeRes();
    await h(makeReq(undefined), res);

    expect(res.statusCode).toBe(400);
  });

  it("refuses a message past the length cap", async () => {
    const h = await handler();
    const res = makeRes();
    await h(makeReq({ message: "x".repeat(5001) }), res);

    expect(res.statusCode).toBe(400);
    expect(state.inserted).toHaveLength(0);
  });

  it("accepts a message exactly at the cap", async () => {
    const h = await handler();
    const res = makeRes();
    await h(makeReq({ message: "x".repeat(5000) }), res);

    expect(res.statusCode).toBe(201);
  });
});

describe("POST /feedback — the optional fields", () => {
  it("stores a rating inside 1-5 as given", async () => {
    const h = await handler();
    const res = makeRes();
    await h(makeReq({ message: "good", rating: 4 }), res);

    expect(state.inserted[0]).toMatchObject({ rating: 4 });
  });

  it("clamps a rating outside 1-5 rather than rejecting the whole submission", async () => {
    // The message is the valuable part. A bad rating must never cost us one.
    for (const [given, expected] of [[9, 5], [0, 1], [-3, 1]] as const) {
      state.inserted = [];
      vi.resetModules();
      const h = await handler();
      await h(makeReq({ message: "still worth keeping", rating: given }), makeRes());
      expect(state.inserted[0], `rating ${given}`).toMatchObject({ rating: expected });
    }
  });

  it("stores no rating when one is not a whole number", async () => {
    const h = await handler();
    const res = makeRes();
    await h(makeReq({ message: "good", rating: 3.5 }), res);

    expect(res.statusCode).toBe(201);
    expect(state.inserted[0]).toMatchObject({ rating: null });
  });

  it("stores no rating when the field is absent or the wrong type", async () => {
    for (const rating of [undefined, "5", null]) {
      state.inserted = [];
      vi.resetModules();
      const h = await handler();
      await h(makeReq({ message: "no rating given", rating }), makeRes());
      expect(state.inserted[0], String(rating)).toMatchObject({ rating: null });
    }
  });

  it("truncates an over-long context rather than refusing the submission", async () => {
    const h = await handler();
    await h(makeReq({ message: "hi", context: "c".repeat(400) }), makeRes());

    const row = state.inserted[0] as { context: string };
    expect(row.context).toHaveLength(200);
  });
});

describe("POST /feedback — when the database is down", () => {
  it("answers 500 rather than pretending the feedback was kept", async () => {
    state.insertThrows = new Error("connection refused");
    const h = await handler();
    const res = makeRes();
    await h(makeReq({ message: "this one gets lost" }), res);

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: "Failed to record feedback" });
  });

  it("logs the failure, so a lost submission leaves a trace", async () => {
    state.insertThrows = new Error("connection refused");
    const h = await handler();
    const req = makeReq({ message: "this one gets lost" });
    await h(req, makeRes());

    expect(req.log.error).toHaveBeenCalled();
  });
});

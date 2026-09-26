import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";

let rows: Array<Record<string, unknown>> = [];
const updates: Array<Record<string, unknown>> = [];
const lookups: unknown[] = [];

vi.mock("drizzle-orm", () => ({
  and: (...args: unknown[]) => ({ op: "and", args }),
  eq: (col: unknown, val: unknown) => ({ op: "eq", col, val }),
}));
vi.mock("@workspace/db", () => {
  const table = { id: "id", userId: "userId", status: "status", pausedAt: "pausedAt" };
  return {
    monitorSubscriptionsTable: table,
    db: {
      select: () => ({ from: () => ({ where: async (w: unknown) => { lookups.push(w); return rows; } }) }),
      update: () => ({ set: (v: Record<string, unknown>) => ({ where: async () => { updates.push(v); } }) }),
    },
  };
});

import router from "./monitorControls";

let user: { id: string } | null = { id: "u1" };
const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  Object.assign(req, { isAuthenticated: () => user !== null, user });
  next();
});
app.use("/api", router);
const server = app.listen(0);
afterAll(() => { server.close(); });
const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/monitor/subscriptions/sub1/pause`;
const patch = (b: unknown) => fetch(url, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });

beforeEach(() => { rows = [{ id: "sub1", userId: "u1", status: "active", pausedAt: null }]; updates.length = 0; lookups.length = 0; user = { id: "u1" }; });

describe("PATCH /monitor/subscriptions/:id/pause", () => {
  it("pauses an active monitor and reports when", async () => {
    const res = await patch({ paused: true });
    expect(res.status).toBe(200);
    const j = await res.json() as { paused: boolean; pausedAt: string };
    expect(j.paused).toBe(true);
    expect(new Date(j.pausedAt).getTime()).toBeGreaterThan(Date.now() - 5000);
    expect(updates[0]!["pausedAt"]).toBeInstanceOf(Date);
  });

  it("resumes by clearing the pause", async () => {
    rows = [{ id: "sub1", userId: "u1", status: "active", pausedAt: new Date("2026-09-01") }];
    const j = await (await patch({ paused: false })).json() as { paused: boolean };
    expect(j.paused).toBe(false);
    expect(updates[0]).toEqual({ pausedAt: null });
  });

  it("pausing twice keeps the original pause time", async () => {
    const earlier = new Date("2026-09-01T00:00:00Z");
    rows = [{ id: "sub1", userId: "u1", status: "active", pausedAt: earlier }];
    await patch({ paused: true });
    expect(updates[0]!["pausedAt"]).toEqual(earlier);
  });

  it("looks the monitor up by id AND owner, so another customer's id is a 404, not a pause", async () => {
    rows = [];
    expect((await patch({ paused: true })).status).toBe(404);
    const flat = JSON.stringify(lookups[0]);
    expect(flat).toContain("u1");
    expect(flat).toContain("sub1");
    expect(updates).toHaveLength(0);
  });

  it("refuses a cancelled monitor", async () => {
    rows = [{ id: "sub1", userId: "u1", status: "cancelled", pausedAt: null }];
    expect((await patch({ paused: true })).status).toBe(409);
    expect(updates).toHaveLength(0);
  });

  it("rejects a body that is not a boolean, and a signed-out caller", async () => {
    expect((await patch({ paused: "yes" })).status).toBe(400);
    expect((await patch({})).status).toBe(400);
    user = null;
    expect((await patch({ paused: true })).status).toBe(401);
    expect(updates).toHaveLength(0);
  });
});

import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";

let row: { off: boolean } | undefined = { off: false };
const updates: Array<Record<string, unknown>> = [];

vi.mock("drizzle-orm", () => ({ eq: (c: unknown, v: unknown) => ({ c, v }) }));
vi.mock("@workspace/db", () => ({
  usersTable: { id: "id", aiAnalysisOptedOut: "aiAnalysisOptedOut" },
  db: {
    select: () => ({ from: () => ({ where: async () => (row ? [row] : []) }) }),
    update: () => ({ set: (v: Record<string, unknown>) => ({ where: async () => { updates.push(v); } }) }),
  },
}));

import router from "./accountPrivacy";

let user: { id: string } | null = { id: "u1" };
const app = express();
app.use(express.json());
app.use((req, _res, next) => { Object.assign(req, { isAuthenticated: () => user !== null, user }); next(); });
app.use("/api", router);
const server = app.listen(0);
afterAll(() => { server.close(); });
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/account/privacy`;
const put = (b: unknown) => fetch(base, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });

beforeEach(() => { row = { off: false }; updates.length = 0; user = { id: "u1" }; });

describe("/account/privacy", () => {
  it("reads as an opt-in: on by default, off once the column is set", async () => {
    expect(await (await fetch(base)).json()).toEqual({ aiAnalysis: true });
    row = { off: true };
    expect(await (await fetch(base)).json()).toEqual({ aiAnalysis: false });
  });
  it("a user with no row reads as on, so a missing row never hides the default", async () => {
    row = undefined;
    expect(await (await fetch(base)).json()).toEqual({ aiAnalysis: true });
  });
  it("turning it off stores an opt-out, and turning it on clears it", async () => {
    await put({ aiAnalysis: false });
    await put({ aiAnalysis: true });
    expect(updates).toEqual([{ aiAnalysisOptedOut: true }, { aiAnalysisOptedOut: false }]);
  });
  it("rejects anything but a boolean and signed-out callers, and stores nothing", async () => {
    expect((await put({ aiAnalysis: "off" })).status).toBe(400);
    expect((await put({})).status).toBe(400);
    user = null;
    expect((await put({ aiAnalysis: false })).status).toBe(401);
    expect((await fetch(base)).status).toBe(401);
    expect(updates).toHaveLength(0);
  });
});

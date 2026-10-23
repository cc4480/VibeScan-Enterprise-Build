/** /account/privacy against a REAL Postgres (BILLING_TEST_DATABASE_URL): the opt-out column is read and written for real. */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("/account/privacy (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let server: Server;
  let base: string;
  let userId: string;
  let signedIn: { id: string } | null;

  const columnOff = async () => {
    const { eq } = await import("drizzle-orm");
    const [row] = await dbMod.db
      .select({ off: dbMod.usersTable.aiAnalysisOptedOut })
      .from(dbMod.usersTable)
      .where(eq(dbMod.usersTable.id, userId));
    return row?.off;
  };
  const put = (b: unknown) => fetch(base, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    const [u] = await dbMod.db
      .insert(dbMod.usersTable)
      .values({ email: `privacy-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com` })
      .returning({ id: dbMod.usersTable.id });
    userId = u!.id;
    const { default: router } = await import("./accountPrivacy");
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { Object.assign(req, { isAuthenticated: () => signedIn !== null, user: signedIn }); next(); });
    app.use("/api", router);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/account/privacy`;
  }, 60_000);

  afterAll(async () => {
    server?.close();
    if (userId) {
      const { eq } = await import("drizzle-orm");
      await dbMod.db.delete(dbMod.usersTable).where(eq(dbMod.usersTable.id, userId));
    }
    await dbMod?.pool?.end?.();
  });

  it("reads as an opt-in: on by default, off once the column is set", async () => {
    signedIn = { id: userId };
    expect(await (await fetch(base)).json()).toEqual({ aiAnalysis: true });
    await put({ aiAnalysis: false });
    expect(await (await fetch(base)).json()).toEqual({ aiAnalysis: false });
    await put({ aiAnalysis: true });
  });

  it("a user with no row reads as on, so a missing row never hides the default", async () => {
    signedIn = { id: "00000000-0000-4000-8000-000000000000" };
    expect(await (await fetch(base)).json()).toEqual({ aiAnalysis: true });
  });

  it("turning it off stores an opt-out, and turning it on clears it", async () => {
    signedIn = { id: userId };
    await put({ aiAnalysis: false });
    expect(await columnOff()).toBe(true);
    await put({ aiAnalysis: true });
    expect(await columnOff()).toBe(false);
  });

  it("rejects anything but a boolean and signed-out callers, and stores nothing", async () => {
    signedIn = { id: userId };
    await put({ aiAnalysis: true });
    expect((await put({ aiAnalysis: "off" })).status).toBe(400);
    expect((await put({})).status).toBe(400);
    signedIn = null;
    expect((await put({ aiAnalysis: false })).status).toBe(401);
    expect((await fetch(base)).status).toBe(401);
    expect(await columnOff()).toBe(false);
  });
});

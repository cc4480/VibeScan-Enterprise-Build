/**
 * The per-scan opt-in for an automatic second account, from request to stored row, against a REAL
 * Postgres (so migration 0024 is proven too). Runs only with GHWIRE_TEST_DATABASE_URL (a disposable
 * database; it truncates scans and users).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";

const URL_ = process.env["GHWIRE_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) {
  process.env["DATABASE_URL"] = URL_;
  // Each accepted scan spends one free trial scan; the suite creates more than the default three.
  process.env["FREE_TRIAL_SCAN_LIMIT"] = "50";
  process.env["ENCRYPTION_KEY"] = Buffer.alloc(32, 7).toString("base64");
}


let app: express.Express;
let dbMod: typeof import("@workspace/db");

const SESSION = { mode: "session", authorized: true, cookie: "sid=abc" } as const;
const OTHER = { mode: "session", authorized: true, cookie: "sid=def" } as const;

suite("scan creation: automatic second account opt-in (real Postgres)", () => {
  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    const { sql } = await import("drizzle-orm");
    await dbMod.db.execute(sql`TRUNCATE scans, users CASCADE`);
    // A registered, verified account: the only kind allowed to store credentials.
    await dbMod.db.insert(dbMod.usersTable).values({ id: "auto-user-1", email: "auto@example.test", passwordHash: "x", emailVerifiedAt: new Date() });
    const { createScanHandler } = await import("./scans");
    app = express();
    app.use(express.json());
    app.post("/scans", (req, res, next) => {
      const log = { info() {}, warn() {}, error() {} };
      Object.assign(req, { log, user: { id: "auto-user-1", email: "auto@example.test" }, isAuthenticated: () => true });
      createScanHandler(req, res).catch(next);
    });
  }, 60_000);

  afterAll(async () => {
    await dbMod?.pool?.end?.();
  });

  async function flagFor(url: string): Promise<boolean | undefined> {
    const { scansTable } = dbMod;
    const { eq } = await import("drizzle-orm");
    const [row] = await dbMod.db.select({ f: scansTable.autoSecondAccount }).from(scansTable).where(eq(scansTable.targetUrl, url));
    return row?.f;
  }

  it("is off by default", async () => {
    const res = await request(app).post("/scans").send({ targetUrl: "http://127.0.0.1:9/default", credentials: SESSION });
    expect(res.status, res.text.replace(/<[^>]+>/g, " ").slice(0, 400)).toBe(201);
    expect(await flagFor("http://127.0.0.1:9/default")).toBe(false);
  });

  it("is stored as on only when asked for", async () => {
    const res = await request(app).post("/scans").send({ targetUrl: "http://127.0.0.1:9/on", credentials: SESSION, autoSecondAccount: true });
    expect(res.status, res.text.replace(/<[^>]+>/g, " ").slice(0, 400)).toBe(201);
    expect(await flagFor("http://127.0.0.1:9/on")).toBe(true);
  });

  it("is not stored as on when the requester supplied a second account of their own", async () => {
    const res = await request(app)
      .post("/scans")
      .send({ targetUrl: "http://127.0.0.1:9/own", credentials: SESSION, secondaryCredentials: OTHER, autoSecondAccount: true });
    expect(res.status, res.text.replace(/<[^>]+>/g, " ").slice(0, 400)).toBe(201);
    expect(await flagFor("http://127.0.0.1:9/own")).toBe(false);
  });

  it("is refused without credentials, before anything is charged or stored", async () => {
    const res = await request(app).post("/scans").send({ targetUrl: "http://127.0.0.1:9/nocreds", autoSecondAccount: true });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/needs credentials/);
    expect(await flagFor("http://127.0.0.1:9/nocreds")).toBeUndefined();
  });

  it("is refused with a 400 when the same session is given as both accounts", async () => {
    const res = await request(app).post("/scans").send({ targetUrl: "http://127.0.0.1:9/same", credentials: SESSION, secondaryCredentials: { ...SESSION, cookie: " sid=abc " } });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/same account as the first/i);
    expect(await flagFor("http://127.0.0.1:9/same")).toBeUndefined();
  });

  it("is refused when the same form login is given twice", async () => {
    const form = { mode: "form", authorized: true, loginUrl: "https://x.example/login", username: "ada@example.com", password: "pw" } as const;
    const res = await request(app).post("/scans").send({ targetUrl: "http://127.0.0.1:9/sameform", credentials: form, secondaryCredentials: { ...form, username: "ADA@example.com" } });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/same account/i);
  });

  it("still accepts two different sessions", async () => {
    const res = await request(app).post("/scans").send({ targetUrl: "http://127.0.0.1:9/diff", credentials: SESSION, secondaryCredentials: OTHER });
    expect(res.status).toBe(201);
  });
});

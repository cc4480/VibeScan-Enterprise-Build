/**
 * Sign-up against a REAL Postgres: the emailed code and the per-network cap.
 *
 * Runs only when a disposable database is supplied, and skips otherwise:
 *
 *   docker run -d --rm --name signup-test-pg -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_DB=signup -p 5441:5432 postgres:16
 *   SIGNUP_TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:5441/signup \
 *     npx vitest run src/routes/signup.integration.test.ts
 *
 * NEVER point it at a database whose data matters: it truncates users.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from "vitest";
import express from "express";
import request from "supertest";

const URL_ = process.env["SIGNUP_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

// The code that would have been emailed, per address.
const sent = new Map<string, string>();
vi.mock("../lib/mailer", () => ({
  sendLoginCode: async (to: string, code: string) => {
    sent.set(to, code);
  },
  sendWelcomeEmail: async () => {},
  addToMarketingAudience: async () => {},
  sendEmailVerification: async () => {},
  sendPasswordReset: async () => {},
}));
// Each test picks the network it signs up from.
vi.mock("../lib/clientIp", () => ({
  clientIp: (req: { headers: Record<string, string | undefined> }) => req.headers["x-test-ip"] ?? "198.51.100.1",
}));

let app: express.Express;
let dbMod: typeof import("@workspace/db");

suite("sign-up (real Postgres)", () => {
  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    const { default: accountRouter } = await import("./account");
    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      (req as any).log = { info() {}, warn() {}, error() {} };
      next();
    });
    app.use(accountRouter);
  }, 60_000);

  beforeEach(async () => {
    const { sql } = await import("drizzle-orm");
    await dbMod.db.execute(sql`TRUNCATE users, pending_registrations, sessions CASCADE`);
    sent.clear();
  }, 30_000);

  afterAll(async () => {
    await dbMod?.pool?.end?.();
  });

  // Each registration comes from its own IP so the in-memory per-IP attempt
  // limiter never interferes; the NETWORK is chosen via the address.
  let ipSeq = 0;
  const start = (email: string, ip: string) =>
    request(app).post("/account/register").set("x-test-ip", ip).send({ email, password: "correct horse battery" });
  const finish = (challenge: string, code: string, ip = `203.0.113.${++ipSeq}`) =>
    request(app).post("/account/register/verify").set("x-test-ip", ip).send({ challenge, code });

  const users = async () => {
    const { usersTable } = dbMod;
    return dbMod.db.select().from(usersTable);
  };

  it("creates NO account until the emailed code comes back", async () => {
    const res = await start("new@example.com", "198.51.100.10");
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ codeRequired: true, sentTo: "ne*@example.com" });
    expect(await users()).toHaveLength(0);

    const done = await finish(res.body.challenge, sent.get("new@example.com")!);
    expect(done.status).toBe(201);
    expect(done.body.user.email).toBe("new@example.com");
    expect(done.headers["set-cookie"]?.[0]).toMatch(/sid=/);

    const [row] = await users();
    expect(row!.emailVerifiedAt).not.toBeNull();
    expect(row!.signupNetwork).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses a wrong code and creates nothing", async () => {
    const res = await start("wrong@example.com", "198.51.100.11");
    const done = await finish(res.body.challenge, "000000" === sent.get("wrong@example.com") ? "111111" : "000000");
    expect(done.status).toBe(401);
    expect(await users()).toHaveLength(0);
  });

  it("spends the challenge after five wrong codes, even for the right one", async () => {
    const res = await start("guess@example.com", "198.51.100.12");
    const right = sent.get("guess@example.com")!;
    const wrong = right === "000000" ? "111111" : "000000";
    for (let i = 0; i < 5; i++) expect((await finish(res.body.challenge, wrong)).status).toBe(401);
    expect((await finish(res.body.challenge, right)).status).toBe(401);
    expect(await users()).toHaveLength(0);
  });

  it("allows 2 accounts per network, refuses the 3rd — and sends it no code", async () => {
    for (const email of ["a@example.com", "b@example.com"]) {
      const res = await start(email, "198.51.100.20");
      expect((await finish(res.body.challenge, sent.get(email)!)).status).toBe(201);
    }
    const third = await start("c@example.com", "198.51.100.20");
    expect(third.status).toBe(429);
    expect(third.body.error).toMatch(/limit/);
    expect(sent.has("c@example.com")).toBe(false);
    expect(await users()).toHaveLength(2);
  });

  it("treats every address in one IPv6 /64 as the same network", async () => {
    for (const [email, ip] of [
      ["v6a@example.com", "2001:db8:1:2::1"],
      ["v6b@example.com", "2001:db8:1:2:ffff::9"],
    ] as const) {
      const res = await start(email, ip);
      expect((await finish(res.body.challenge, sent.get(email)!)).status).toBe(201);
    }
    expect((await start("v6c@example.com", "2001:db8:1:2:aaaa:bbbb:cccc:dddd")).status).toBe(429);
    // A different /64 is a different network.
    expect((await start("v6d@example.com", "2001:db8:1:3::1")).status).toBe(202);
  });

  it("re-checks the cap when the code is redeemed", async () => {
    // Three sign-ups start while the network is still under the cap...
    const pending = [];
    for (const email of ["r1@example.com", "r2@example.com", "r3@example.com"]) {
      pending.push({ email, res: await start(email, "198.51.100.30") });
    }
    // ...but only two may finish.
    const results = [];
    for (const p of pending) results.push((await finish(p.res.body.challenge, sent.get(p.email)!)).status);
    expect(results).toEqual([201, 201, 429]);
    expect(await users()).toHaveLength(2);
  });

  it("does not count accounts older than the window", async () => {
    const { usersTable } = dbMod;
    const { networkKey } = await import("../lib/signupNetwork");
    const old = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000);
    await dbMod.db.insert(usersTable).values([
      { email: "old1@example.com", signupNetwork: networkKey("198.51.100.40"), createdAt: old },
      { email: "old2@example.com", signupNetwork: networkKey("198.51.100.40"), createdAt: old },
    ]);
    expect((await start("fresh@example.com", "198.51.100.40")).status).toBe(202);
  });

  it("still refuses an address that already has an account", async () => {
    const res = await start("dup@example.com", "198.51.100.50");
    await finish(res.body.challenge, sent.get("dup@example.com")!);
    expect((await start("dup@example.com", "198.51.100.51")).status).toBe(409);
  });
});

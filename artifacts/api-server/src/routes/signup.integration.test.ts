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
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { startMailSink, type MailSink } from "../lib/mailSink.testkit";

const URL_ = process.env["SIGNUP_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

// Mail goes through the real mailer to a real local endpoint (lib/mailSink.testkit.ts), which records it.
let sink: MailSink;
const NOTICE_SUBJECT = "You already have a SecScan.us account";
/** Addresses that were told "you already have an account" instead of being sent a code. */
const notices = () => sink.mail.filter((m) => m.subject === NOTICE_SUBJECT).map((m) => m.to[0]);
/** Sign-in codes mailed, in total. */
const codesSent = () => sink.mail.filter((m) => /sign-in code/i.test(m.subject)).length;
const codeTo = (email: string) => sink.loginCodeTo(email);

let app: express.Express;
let dbMod: typeof import("@workspace/db");

suite("sign-up (real Postgres)", () => {
  beforeAll(async () => {
    sink = await startMailSink();
    // Behind Cloudflare the client address is the last X-Forwarded-For entry, which is how each test picks its network.
    process.env["BEHIND_CLOUDFLARE"] = "true";
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
    sink.clear();
    // The per-address limiter is in memory and keyed by address, so tests that
    // reuse one must not inherit each other's count.
    const { attempts } = await import("./accountShared");
    attempts.clear();
  }, 30_000);

  afterAll(async () => {
    await sink?.stop();
    delete process.env["BEHIND_CLOUDFLARE"];
    await dbMod?.pool?.end?.();
  });

  // Each registration comes from its own IP so the in-memory per-IP attempt
  // limiter never interferes; the NETWORK is chosen via the address.
  let ipSeq = 0;
  const start = (email: string, ip: string, password = "correct horse battery") =>
    request(app).post("/account/register").set("x-forwarded-for", ip).send({ email, password });
  const finish = (challenge: string, code: string, ip = `203.0.113.${++ipSeq}`) =>
    request(app).post("/account/register/verify").set("x-forwarded-for", ip).send({ challenge, code });

  const users = async () => {
    const { usersTable } = dbMod;
    return dbMod.db.select().from(usersTable);
  };

  it("creates NO account until the emailed code comes back", async () => {
    const res = await start("new@example.com", "198.51.100.10");
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ codeRequired: true, sentTo: "ne*@example.com" });
    expect(await users()).toHaveLength(0);

    const done = await finish(res.body.challenge, codeTo("new@example.com")!);
    expect(done.status).toBe(201);
    expect(done.body.user.email).toBe("new@example.com");
    expect(done.headers["set-cookie"]?.[0]).toMatch(/sid=/);

    const [row] = await users();
    expect(row!.emailVerifiedAt).not.toBeNull();
    expect(row!.signupNetwork).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses a wrong code and creates nothing", async () => {
    const res = await start("wrong@example.com", "198.51.100.11");
    const done = await finish(res.body.challenge, "000000" === codeTo("wrong@example.com") ? "111111" : "000000");
    expect(done.status).toBe(401);
    expect(await users()).toHaveLength(0);
  });

  it("spends the challenge after five wrong codes, even for the right one", async () => {
    const res = await start("guess@example.com", "198.51.100.12");
    const right = codeTo("guess@example.com")!;
    const wrong = right === "000000" ? "111111" : "000000";
    for (let i = 0; i < 5; i++) expect((await finish(res.body.challenge, wrong)).status).toBe(401);
    expect((await finish(res.body.challenge, right)).status).toBe(401);
    expect(await users()).toHaveLength(0);
  });

  it("allows 2 accounts per network, refuses the 3rd — and sends it no code", async () => {
    for (const email of ["a@example.com", "b@example.com"]) {
      const res = await start(email, "198.51.100.20");
      expect((await finish(res.body.challenge, codeTo(email)!)).status).toBe(201);
    }
    const third = await start("c@example.com", "198.51.100.20");
    expect(third.status).toBe(429);
    expect(third.body.error).toMatch(/limit/);
    expect((codeTo("c@example.com") !== undefined)).toBe(false);
    expect(await users()).toHaveLength(2);
  });

  it("treats every address in one IPv6 /64 as the same network", async () => {
    for (const [email, ip] of [
      ["v6a@example.com", "2001:db8:1:2::1"],
      ["v6b@example.com", "2001:db8:1:2:ffff::9"],
    ] as const) {
      const res = await start(email, ip);
      expect((await finish(res.body.challenge, codeTo(email)!)).status).toBe(201);
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
    for (const p of pending) results.push((await finish(p.res.body.challenge, codeTo(p.email)!)).status);
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

  // ── An address that already has an account ─────────────────────────────────
  //
  // Sign-up used to answer these with 409 "already exists", which let anyone ask
  // "does this address have an account?" one request at a time. It now answers
  // them exactly as it answers a new address, and emails the owner instead.

  /** Create an account through the real flow and return its row, to show later that nothing touched it. */
  async function existingAccount(email: string, ip: string) {
    const res = await start(email, ip);
    expect((await finish(res.body.challenge, codeTo(email)!)).status).toBe(201);
    sink.clear();
    const { attempts } = await import("./accountShared");
    attempts.clear();
    const [row] = await users();
    return row!;
  }

  const sessionCount = async () => (await dbMod.db.select().from(dbMod.sessionsTable)).length;
  /** Sign-ups with a code still outstanding. Finished ones are kept, marked used. */
  const pendingRows = async () =>
    (await dbMod.db.select().from(dbMod.pendingRegistrationsTable)).filter((p) => !p.usedAt);

  describe("an address that already has an account", () => {
    it("is answered exactly like a new address, and its owner is emailed instead of sent a code", async () => {
      const before = await existingAccount("owner@example.com", "198.51.100.50");
      const sessionsBefore = await sessionCount();

      const fresh = await start("fresh@example.com", "198.51.100.51");
      // A DIFFERENT password: it must not replace the existing one.
      const dup = await start("owner@example.com", "198.51.100.52", "a different password entirely");

      // Same status, same body shape, same kind of values.
      expect(fresh.status).toBe(202);
      expect(dup.status).toBe(fresh.status);
      expect(Object.keys(dup.body).sort()).toEqual(Object.keys(fresh.body).sort());
      expect(dup.body.codeRequired).toBe(true);
      expect(dup.body.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(fresh.body.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(dup.body.sentTo).toBe("ow***@example.com");
      expect(dup.headers["content-type"]).toBe(fresh.headers["content-type"]);
      // No session for either: sign-up only ever starts one at the second step.
      expect(dup.headers["set-cookie"]).toBeUndefined();
      expect(fresh.headers["set-cookie"]).toBeUndefined();

      // The new address got a code; the existing one got the notice and no code.
      expect((codeTo("fresh@example.com") !== undefined)).toBe(true);
      expect((codeTo("owner@example.com") !== undefined)).toBe(false);
      expect(notices()).toEqual(["owner@example.com"]);

      // And the existing account is exactly as it was.
      const rows = await users();
      expect(rows).toHaveLength(1);
      expect(rows[0]).toEqual(before);
      expect(await sessionCount()).toBe(sessionsBefore);
      // Nothing was left pending for it either: only the new address has a code outstanding.
      expect((await pendingRows()).map((p) => p.email)).toEqual(["fresh@example.com"]);
    });

    it("gets a challenge nothing can redeem, which fails like a wrong code and issues no session", async () => {
      await existingAccount("owner@example.com", "198.51.100.53");
      const dup = await start("owner@example.com", "198.51.100.54");
      const real = await start("fresh@example.com", "198.51.100.55");

      const realCode = codeTo("fresh@example.com")!;
      const realWrong = await finish(real.body.challenge, realCode === "000000" ? "111111" : "000000");
      expect(realWrong.status).toBe(401);

      for (const code of ["000000", "123456", "654321", "999999", "111111", "222222"]) {
        const res = await finish(dup.body.challenge, code);
        // The very response a wrong code on a real challenge gets, however many are tried.
        expect(res.status).toBe(401);
        expect(res.body).toEqual(realWrong.body);
        expect(res.headers["set-cookie"]).toBeUndefined();
      }
      expect(await users()).toHaveLength(1);
    });

    it("does the same work as a new address: the password is hashed on both paths", async () => {
      // Not observable by counting calls, so by cost: hashing is deliberately slow, and an existing address that
      // skipped it would answer far faster than a new one, which would itself reveal that the account exists.
      await existingAccount("owner@example.com", "198.51.100.56");
      const { hashPassword } = await import("../lib/password");
      const t0 = Date.now();
      await hashPassword("a password to time");
      const oneHash = Date.now() - t0;

      const timed = async (email: string, ip: string) => {
        const t = Date.now();
        expect((await start(email, ip)).status).toBe(202);
        return Date.now() - t;
      };
      const fresh = await timed("fresh@example.com", "198.51.100.57");
      const existing = await timed("owner@example.com", "198.51.100.58");
      expect(fresh).toBeGreaterThanOrEqual(oneHash * 0.5);
      expect(existing).toBeGreaterThanOrEqual(oneHash * 0.5);
    });

    it("does not claim a legacy anonymous identity for an account that already exists", async () => {
      await existingAccount("owner@example.com", "198.51.100.59");
      const anonId = randomUUID();
      await dbMod.db.insert(dbMod.usersTable).values({ id: anonId });

      const res = await request(app)
        .post("/account/register")
        .set("x-forwarded-for", "198.51.100.60")
        .set("Authorization", `Bearer ${anonId}`)
        .send({ email: "owner@example.com", password: "correct horse battery" });

      expect(res.status).toBe(202);
      const anon = (await users()).find((u) => u.id === anonId)!;
      expect(anon.email).toBeNull();
      expect(anon.passwordHash).toBeNull();
      expect(await pendingRows()).toHaveLength(0);
    });

    it("is refused by a capped network exactly as a new address is, and is sent nothing", async () => {
      for (const email of ["a@example.com", "b@example.com"]) {
        const res = await start(email, "198.51.100.61");
        expect((await finish(res.body.challenge, codeTo(email)!)).status).toBe(201);
      }
      sink.clear();

      const existing = await start("a@example.com", "198.51.100.61");
      const fresh = await start("c@example.com", "198.51.100.61");

      expect(existing.status).toBe(429);
      expect(fresh.status).toBe(429);
      expect(existing.body).toEqual(fresh.body);
      // A capped network cannot use sign-up to mail anyone, existing account or not.
      // (A welcome email for the earlier sign-ups may still be in flight; what must not exist is a code or a notice.)
      expect(notices()).toEqual([]);
      expect(codesSent()).toBe(0);
    });

    it("fails the same way as a new address when the email cannot be sent", async () => {
      await existingAccount("owner@example.com", "198.51.100.62");
      sink.respondWith(500); // the provider is refusing mail

      const dup = await start("owner@example.com", "198.51.100.63");
      const fresh = await start("fresh@example.com", "198.51.100.64");

      expect(fresh.status).toBe(502);
      expect(dup.status).toBe(502);
      expect(dup.body).toEqual(fresh.body);
      expect(await users()).toHaveLength(1);
    });

    it("is limited per address, identically for an existing and a new one, across different networks", async () => {
      await existingAccount("owner@example.com", "198.51.100.65");

      // Ten requests from ten different IPs are let through for each address; the eleventh is refused.
      const last = async (email: string, base: number) => {
        let res = await start(email, `198.51.100.${base}`);
        for (let i = 1; i <= 10; i++) res = await start(email, `198.51.100.${base + i}`);
        return res;
      };
      const forExisting = await last("owner@example.com", 100);
      const forNew = await last("fresh@example.com", 120);

      expect(forExisting.status).toBe(429);
      expect(forNew.status).toBe(429);
      expect(forExisting.body).toEqual(forNew.body);
      // Those ten each mailed someone, but the eleventh did not.
      expect(notices().filter((n) => n === "owner@example.com")).toHaveLength(10);
    }, 60_000);
  });

  it("still refuses to create an account at step two if the address was taken in the meantime, and starts no session", async () => {
    // Reachable only with a valid code, i.e. by someone who can read that mailbox, so it is not an oracle.
    const res = await start("race@example.com", "198.51.100.70");
    const code = codeTo("race@example.com")!;
    await dbMod.db.insert(dbMod.usersTable).values({ email: "race@example.com" });

    const done = await finish(res.body.challenge, code);

    expect(done.status).toBe(409);
    expect(done.headers["set-cookie"]).toBeUndefined();
    expect(await users()).toHaveLength(1);
    expect(await sessionCount()).toBe(0);
  });
});

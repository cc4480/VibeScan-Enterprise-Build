/**
 * The free-scan cap exists to get people testing the scanner and saying what happened, and this route is the only
 * thing that catches what they say. So the failures that matter are losing a submission, and refusing one from
 * someone who never signed in: the whole point being that account creation is not the price of being heard.
 *
 * Over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL), with the real per-address limiter. Each
 * test sends from an address of its own, as the client address is read behind Cloudflare in production.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Writable } from "node:stream";
import pino from "pino";
import { dbSuiteOf, useRealDb, openDb, startApp, type TestApp } from "../lib/realDb.testkit";

useRealDb();

const RUN = `fb-${Date.now()}`;

dbSuiteOf(describe)("POST /feedback (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let eq: typeof import("drizzle-orm").eq;
  let like: typeof import("drizzle-orm").like;
  let sql: typeof import("drizzle-orm").sql;
  let app: TestApp;
  let savedCf: string | undefined;
  const logged: string[] = [];
  let n = 0;
  /** A fresh client address per call, so one test's submissions never count against another's. */
  const newIp = () => `198.51.${Math.floor(++n / 250)}.${(n % 250) + 1}`;
  const msg = (tail: string) => `${RUN} ${tail}`;

  const send = (body: unknown, ip = newIp()) =>
    fetch(`${app.base}/feedback`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": ip },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const stored = async (message: string) => (await dbMod.db.select().from(dbMod.feedbackTable).where(eq(dbMod.feedbackTable.message, message)))[0];

  beforeAll(async () => {
    dbMod = await openDb();
    ({ eq, like, sql } = await import("drizzle-orm"));
    savedCf = process.env["BEHIND_CLOUDFLARE"];
    process.env["BEHIND_CLOUDFLARE"] = "true";
    const { default: router } = await import("./feedback");
    const log = pino({ level: "info" }, new Writable({ write(c, _e, cb) { logged.push(String(c)); cb(); } }));
    app = startApp(router, { log });
    await dbMod.db.execute(sql`DO $$ BEGIN
      IF to_regclass('public.feedback') IS NULL AND to_regclass('public.feedback_offline') IS NOT NULL THEN
        ALTER TABLE feedback_offline RENAME TO feedback;
      END IF; END $$`);
  }, 60_000);

  afterAll(async () => {
    app?.server.close();
    if (savedCf === undefined) delete process.env["BEHIND_CLOUDFLARE"];
    else process.env["BEHIND_CLOUDFLARE"] = savedCf;
    await dbMod.db.delete(dbMod.feedbackTable).where(like(dbMod.feedbackTable.message, `${RUN}%`));
    await dbMod?.pool?.end?.();
  });

  describe("how often one address may send", () => {
    it("answers 429 to the submission after the hourly allowance from one address", async () => {
      app.as(null);
      const ip = newIp();
      for (let i = 0; i < 10; i++) expect((await send({ message: msg(`allowance ${i}`) }, ip)).status, `submission ${i + 1}`).toBe(201);
      expect((await send({ message: msg("one too many") }, ip)).status).toBe(429);
      expect(await stored(msg("one too many"))).toBeUndefined(); // refused, so not kept
    });

    it("keeps a different address's allowance separate", async () => {
      app.as(null);
      const ip = newIp();
      for (let i = 0; i < 10; i++) await send({ message: msg(`separate ${i}`) }, ip);
      expect((await send({ message: msg("from elsewhere") })).status).toBe(201);
    });
  });

  describe("who may submit", () => {
    it("accepts a submission from someone who is not signed in", async () => {
      // The reason userId is nullable. An anonymous scan is still a real user with a real opinion, and requiring an
      // account here would silently filter the feedback down to people who already committed to the product.
      app.as(null);
      const res = await send({ message: msg("the report was clearer than I expected") });
      expect(res.status).toBe(201);
      expect(await res.json()).toEqual({ recorded: true });
      expect(await stored(msg("the report was clearer than I expected"))).toMatchObject({ userId: null, email: null });
    });

    it("attaches the account when the submitter is signed in", async () => {
      app.as({ id: "user-fb-1", email: "someone@example.com" });
      const res = await send({ message: msg("found a false positive on my staging box") });
      expect(res.status).toBe(201);
      expect(await stored(msg("found a false positive on my staging box"))).toMatchObject({ userId: "user-fb-1", email: "someone@example.com" });
    });
  });

  describe("what it refuses", () => {
    beforeAll(() => app.as(null));

    it("refuses an empty message, and one that is only whitespace", async () => {
      expect((await send({ message: "" })).status).toBe(400);
      expect((await send({ message: "   \n\t  " })).status).toBe(400);
    });

    it("refuses a missing body without throwing", async () => {
      expect((await send(undefined)).status).toBe(400);
    });

    it("refuses a message past the length cap, and accepts one exactly at it", async () => {
      expect((await send({ message: "x".repeat(5001) })).status).toBe(400);
      const exactly = msg("") + "x".repeat(5000 - msg("").length);
      expect(exactly).toHaveLength(5000);
      expect((await send({ message: exactly })).status).toBe(201);
      expect((await stored(exactly))?.message).toHaveLength(5000);
    });
  });

  describe("the optional fields", () => {
    beforeAll(() => app.as(null));

    it("stores a rating inside 1-5 as given", async () => {
      await send({ message: msg("good"), rating: 4 });
      expect((await stored(msg("good")))?.rating).toBe(4);
    });

    it("clamps a rating outside 1-5 rather than rejecting the whole submission", async () => {
      // The message is the valuable part. A bad rating must never cost us one.
      for (const [given, expected] of [[9, 5], [0, 1], [-3, 1]] as const) {
        const message = msg(`still worth keeping ${given}`);
        expect((await send({ message, rating: given })).status).toBe(201);
        expect((await stored(message))?.rating, `rating ${given}`).toBe(expected);
      }
    });

    it("stores no rating when one is not a whole number", async () => {
      const message = msg("half a star");
      expect((await send({ message, rating: 3.5 })).status).toBe(201);
      expect((await stored(message))?.rating).toBeNull();
    });

    it("stores no rating when the field is absent or the wrong type", async () => {
      for (const [i, rating] of [undefined, "5", null].entries()) {
        const message = msg(`no rating given ${i}`);
        await send({ message, rating });
        expect((await stored(message))?.rating, String(rating)).toBeNull();
      }
    });

    it("truncates an over-long context rather than refusing the submission", async () => {
      const message = msg("hi");
      expect((await send({ message, context: "c".repeat(400) })).status).toBe(201);
      expect((await stored(message))?.context).toHaveLength(200);
    });
  });

  // The failure is real: the table is taken away (a half-migrated deploy) and put straight back.
  describe("when the database is down", () => {
    it("answers 500 rather than pretending the feedback was kept, and logs it so a lost submission leaves a trace", async () => {
      app.as(null);
      const message = msg("this one gets lost");
      logged.length = 0;
      await dbMod.db.execute(sql`ALTER TABLE feedback RENAME TO feedback_offline`);
      try {
        const res = await send({ message });
        expect(res.status).toBe(500);
        expect(await res.json()).toEqual({ error: "Failed to record feedback" });
      } finally {
        await dbMod.db.execute(sql`ALTER TABLE feedback_offline RENAME TO feedback`);
      }
      expect(logged.join("")).toContain('"level":50'); // pino error level
      expect(await stored(message)).toBeUndefined();
    });
  });
});

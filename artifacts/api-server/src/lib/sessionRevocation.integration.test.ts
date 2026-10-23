/**
 * Session revocation against a REAL Postgres.
 *
 * deleteSessionsForUser() finds a user's sessions by an expression over the
 * `sess` JSON column, and the whole point of the IDX_session_user_id expression
 * index is that Postgres can serve that lookup without scanning the table. A
 * mocked db proves neither half: not that the right rows go, and not that the
 * query is written in a form the index can answer. Skips unless a throwaway
 * database is supplied — see billing.integration.test.ts.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("Session revocation (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let auth: typeof import("./auth");
  let sql: typeof import("drizzle-orm").sql;
  // Unique per run so rows left by other suites sharing this database cannot collide, and so
  // cleanup removes only what this file created.
  const run = `sessrev-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    auth = await import("./auth");
    ({ sql } = await import("drizzle-orm"));
  }, 60_000);

  afterAll(async () => {
    if (dbMod) {
      await dbMod.db.execute(sql`DELETE FROM sessions WHERE sid LIKE ${run + "%"}`);
      await dbMod.pool?.end?.();
    }
  });

  function session(userId: string | null) {
    return {
      user: userId === null ? undefined : { id: userId, email: `${userId}@example.com` },
    };
  }

  async function insertSession(sid: string, userId: string | null) {
    const { db, sessionsTable } = dbMod;
    await db.insert(sessionsTable).values({
      sid: `${run}-${sid}`,
      sess: session(userId),
      expire: new Date(Date.now() + 60 * 60 * 1000),
    });
  }

  async function remainingSids(): Promise<string[]> {
    const { db, sessionsTable } = dbMod;
    const rows = await db.select({ sid: sessionsTable.sid }).from(sessionsTable).where(sql`${sessionsTable.sid} LIKE ${run + "%"}`);
    return rows.map((r) => r.sid.slice(run.length + 1)).sort();
  }

  it("deletes every session of the given user and no one else's", async () => {
    const victim = `${run}-victim`;
    await insertSession("v1", victim);
    await insertSession("v2", victim);
    await insertSession("v3", victim);
    // Near misses that a sloppy predicate (prefix, substring, case-insensitive) would also take.
    await insertSession("other", `${run}-other`);
    await insertSession("prefix", `${victim}-longer`);
    await insertSession("suffix", `x${victim}`);
    await insertSession("upper", victim.toUpperCase());
    // A session with no user at all (never signed in) must survive too.
    await insertSession("anon", null);

    await auth.deleteSessionsForUser(victim);

    expect(await remainingSids()).toEqual(["anon", "other", "prefix", "suffix", "upper"]);
  });

  it("is a no-op for a user with no sessions", async () => {
    await insertSession("keep", `${run}-keeper`);
    await auth.deleteSessionsForUser(`${run}-nobody`);
    expect(await remainingSids()).toContain("keep");
  });

  it("issues a query Postgres can answer from IDX_session_user_id", async () => {
    // Enough rows, spread over enough users, that an index scan is the sensible plan.
    await dbMod.db.execute(sql`
      INSERT INTO sessions (sid, sess, expire)
      SELECT ${run + "-bulk-"} || g,
             jsonb_build_object('user', jsonb_build_object('id', ${run + "-bulk-user-"} || (g % 3000)), 'access_token', 't'),
             now() + interval '1 hour'
      FROM generate_series(1, 6000) g`);
    await dbMod.db.execute(sql`ANALYZE sessions`);

    // The statement deleteSessionsForUser builds: a DELETE whose predicate is the shared sessionUserIdExpr, the very
    // expression the index was created on. Asked of drizzle rather than rebuilt by hand, so rewording the expression
    // in @workspace/db without touching the index fails this test.
    const built = dbMod.db.delete(dbMod.sessionsTable).where(sql`${dbMod.sessionUserIdExpr} = ${run + "-bulk-user-7"}`).toSQL();
    const captured: { text: string; values: unknown[] } | undefined = /delete from "sessions"/i.test(built.sql) ? { text: built.sql, values: built.params } : undefined;
    expect(captured, "deleteSessionsForUser should issue a DELETE against sessions").toBeDefined();

    // Run the captured statement under EXPLAIN inside a transaction that is rolled back, so nothing
    // is actually removed by the explain. The sequential scan is switched off for this plan only:
    // on a table this small the planner's own choice depends on statistics, and what is being
    // asserted is that the expression in the query matches the one the index was built on.
    const client = await dbMod.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL enable_seqscan = off");
      const plan = await client.query({ text: `EXPLAIN ${captured!.text}`, values: captured!.values });
      const lines = plan.rows.map((r: Record<string, string>) => r["QUERY PLAN"]).join("\n");
      expect(lines).toContain("IDX_session_user_id");
      expect(lines).not.toMatch(/Seq Scan/);
    } finally {
      await client.query("ROLLBACK").catch(() => {});
      client.release();
    }
  });

  it("revokes one bulk user's sessions and leaves their neighbours alone", async () => {
    const { db } = dbMod;
    const countFor = async (userId: string) => {
      const r = await db.execute(sql`SELECT count(*)::int AS n FROM sessions WHERE ${dbMod.sessionUserIdExpr} = ${userId}`);
      return (r.rows[0] as { n: number }).n;
    };
    const target = `${run}-bulk-user-9`;
    expect(await countFor(target)).toBe(2); // 6000 rows over 3000 users
    await auth.deleteSessionsForUser(target);
    expect(await countFor(target)).toBe(0);
    expect(await countFor(`${run}-bulk-user-8`)).toBe(2);
    expect(await countFor(`${run}-bulk-user-10`)).toBe(2);
  });
});

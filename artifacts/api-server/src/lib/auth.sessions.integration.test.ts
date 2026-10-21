/**
 * Session ids and session contents at rest, against a REAL Postgres.
 *
 * What these pin:
 *  - sessions.sid holds sha256(cookie), never the cookie, so a leaked table
 *    cannot be replayed as a Cookie header.
 *  - A valid cookie still resolves; a tampered cookie, or the stored hash
 *    itself, does not.
 *  - Upstream OIDC tokens are not written into sess.
 *  - Migrations 0031 and 0032 do the same conversion to rows that already
 *    exist. They are run here inside a transaction that is rolled back, so the
 *    SQL in the committed files is the SQL under test.
 *
 * Skips unless a throwaway database is supplied (see billing.testkit.ts):
 *   BILLING_TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:5432/billing_data
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const MIGRATIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../lib/db/migrations",
);

/** The executable statements of a migration file, with its comment lines removed. */
function statementsOf(file: string): string[] {
  const text = readFileSync(path.join(MIGRATIONS_DIR, file), "utf8")
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");
  return text
    .split(/;\s*(?:\n|$)/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => `${s};`);
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

suite("session ids and contents at rest (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let auth: typeof import("./auth");
  let sqlTag: typeof import("drizzle-orm").sql;
  const userId = `sidtest-${randomUUID()}`;
  const user = { id: userId, email: null, firstName: null, lastName: null, profileImageUrl: null };

  const storedRowsFor = async (id: string) => {
    const rows = await dbMod.db
      .select({ sid: dbMod.sessionsTable.sid, sess: dbMod.sessionsTable.sess })
      .from(dbMod.sessionsTable)
      .where(sqlTag`${dbMod.sessionUserIdExpr} = ${id}`);
    return rows;
  };

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    auth = await import("./auth");
    ({ sql: sqlTag } = await import("drizzle-orm"));
  }, 60_000);

  afterAll(async () => {
    if (dbMod) {
      await dbMod.db.execute(sqlTag`DELETE FROM sessions WHERE ${dbMod.sessionUserIdExpr} LIKE 'sidtest-%'`);
      await dbMod.pool?.end?.();
    }
  });

  it("stores sha256 of the session id, not the cookie itself", async () => {
    const cookie = await auth.createSession({ user });
    const rows = await storedRowsFor(userId);
    const mine = rows.filter((r) => r.sid === auth.hashSessionId(cookie));

    expect(mine).toHaveLength(1);
    expect(rows.some((r) => r.sid === cookie)).toBe(false);
    expect(mine[0]!.sid).toBe(sha256(cookie));
    expect(mine[0]!.sid).toMatch(/^[0-9a-f]{64}$/);
  });

  it("a valid cookie still resolves to its user", async () => {
    const cookie = await auth.createSession({ user });
    const session = await auth.getSession(cookie);
    expect(session?.user.id).toBe(userId);
  });

  it("a tampered cookie does not resolve, and neither does the stored hash", async () => {
    const cookie = await auth.createSession({ user });

    expect(await auth.getSession(cookie.slice(0, -1) + (cookie.endsWith("0") ? "1" : "0"))).toBeNull();
    expect(await auth.getSession(`${cookie}x`)).toBeNull();
    // The value at rest is not a credential: presenting it as a cookie must fail.
    expect(await auth.getSession(auth.hashSessionId(cookie))).toBeNull();
  });

  it("logout with a tampered cookie does not revoke the real session", async () => {
    const cookie = await auth.createSession({ user });
    await auth.deleteSession(cookie + "0");
    expect((await auth.getSession(cookie))?.user.id).toBe(userId);

    await auth.deleteSession(cookie);
    expect(await auth.getSession(cookie)).toBeNull();
  });

  it("does not persist upstream OIDC tokens into sess", async () => {
    const cookie = await auth.createSession({
      user,
      access_token: "UPSTREAM-ACCESS-SECRET",
      refresh_token: "UPSTREAM-REFRESH-SECRET",
      expires_at: Date.now() + 3600_000,
    });
    const [row] = (await storedRowsFor(userId)).filter((r) => r.sid === auth.hashSessionId(cookie));
    expect(Object.keys(row!.sess as Record<string, unknown>).sort()).toEqual(["user"]);
    expect(JSON.stringify(row!.sess)).not.toContain("UPSTREAM");
  });

  it("GET /logout signs out with the raw cookie, and ignores a cross-site link", async () => {
    const express = (await import("express")).default;
    const cookieParser = (await import("cookie-parser")).default;
    const request = (await import("supertest")).default;
    const { default: authRouter } = await import("../routes/auth");
    const app = express();
    app.use(cookieParser());
    app.use(authRouter);

    const cookie = await auth.createSession({ user });
    const cross = await request(app).get("/logout").set("Cookie", `sid=${cookie}`).set("Sec-Fetch-Site", "cross-site");
    expect(cross.status).toBe(302);
    expect((await auth.getSession(cookie))?.user.id).toBe(userId);

    const res = await request(app).get("/logout").set("Cookie", `sid=${cookie}`).set("Sec-Fetch-Site", "same-origin");
    expect(res.status).toBe(302);
    expect(res.headers["location"]).toBe("/");
    expect(await auth.getSession(cookie)).toBeNull();
  });

  it("migration 0031 hashes rows that already existed, in place", async () => {
    const raw = `legacy-${randomUUID()}-${"a".repeat(20)}`;
    const legacyUser = `sidtest-legacy-${randomUUID()}`;
    const statements = statementsOf("0031_hash_session_ids.sql");
    expect(statements).toHaveLength(1);

    await expect(
      dbMod.db.transaction(async (tx) => {
        await tx.execute(sqlTag`INSERT INTO sessions (sid, sess, expire)
          VALUES (${raw}, ${JSON.stringify({ user: { id: legacyUser } })}::jsonb, now() + interval '1 day')`);
        for (const s of statements) await tx.execute(sqlTag.raw(s));
        const hashed = await tx.execute(sqlTag`SELECT sid FROM sessions WHERE sid = ${sha256(raw)}`);
        expect(hashed.rows).toHaveLength(1);
        const stillRaw = await tx.execute(sqlTag`SELECT sid FROM sessions WHERE sid = ${raw}`);
        expect(stillRaw.rows).toHaveLength(0);
        throw new Error("ROLLBACK");
      }),
    ).rejects.toThrow("ROLLBACK");

    // Rolled back: the fixture row was never committed.
    const left = await dbMod.db.execute(sqlTag`SELECT 1 FROM sessions WHERE sess->'user'->>'id' = ${legacyUser}`);
    expect(left.rows).toHaveLength(0);
  });

  it("migration 0032 strips upstream tokens from rows that already existed", async () => {
    const legacyUser = `sidtest-tokens-${randomUUID()}`;
    const statements = statementsOf("0032_strip_upstream_tokens_from_sessions.sql");
    expect(statements).toHaveLength(1);

    await expect(
      dbMod.db.transaction(async (tx) => {
        await tx.execute(sqlTag`INSERT INTO sessions (sid, sess, expire) VALUES (${randomUUID()},
          ${JSON.stringify({ user: { id: legacyUser }, access_token: "A", refresh_token: "R", expires_at: 1 })}::jsonb,
          now() + interval '1 day')`);
        for (const s of statements) await tx.execute(sqlTag.raw(s));
        const res = await tx.execute(sqlTag`SELECT sess FROM sessions WHERE sess->'user'->>'id' = ${legacyUser}`);
        expect(res.rows).toHaveLength(1);
        expect(Object.keys((res.rows[0] as { sess: object }).sess)).toEqual(["user"]);
        throw new Error("ROLLBACK");
      }),
    ).rejects.toThrow("ROLLBACK");
  });
});

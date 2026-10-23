/**
 * Account deletion against a REAL Postgres: every table that holds a user id
 * must be empty for that user afterwards.
 *
 * The list of tables is not taken from routes/accountDelete.ts. It is read from
 * the drizzle schema: any table with a `user_id` or `anon_user_id` column, plus
 * `users` itself. The test seeds one row per such table for the account, and a
 * second account whose rows must survive, then calls DELETE /account and checks
 * the first account has nothing left anywhere. A table added to the schema
 * without a matching delete fails here, and that is the point.
 *
 * Skips unless a throwaway database is supplied (see billing.testkit.ts):
 *   BILLING_TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:5432/billing_data
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const DAY = 24 * 60 * 60 * 1000;
const USER_ID_COLUMNS = new Set(["user_id", "anon_user_id"]);
const USERS_TABLE = "users";

suite("account deletion removes every row keyed to the user (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let registerAccountDelete: typeof import("./accountDelete").registerAccountDelete;
  let pgCore: typeof import("drizzle-orm/pg-core");
  let drizzleMod: typeof import("drizzle-orm");

  const alice = `del-alice-${randomUUID()}`;
  const bob = `del-bob-${randomUUID()}`;

  /** Tables that hold a user id, read from the schema. */
  function userTables(): { name: string; table: unknown; cols: ReturnType<typeof pgCore.getTableConfig>["columns"] }[] {
    const out: { name: string; table: unknown; cols: ReturnType<typeof pgCore.getTableConfig>["columns"] }[] = [];
    for (const value of Object.values(dbMod)) {
      if (!drizzleMod.is(value, pgCore.PgTable)) continue;
      const cfg = pgCore.getTableConfig(value as never);
      const hasUserCol = cfg.columns.some((c) => USER_ID_COLUMNS.has(c.name));
      if (hasUserCol || cfg.name === USERS_TABLE) out.push({ name: cfg.name, table: value, cols: cfg.columns });
    }
    return out;
  }

  /** Seeds one row per user table for `userId`, parents before children. */
  async function seedAccount(userId: string): Promise<void> {
    const tables = userTables();
    const names = new Set(tables.map((t) => t.name));
    const seeded = new Map<string, Record<string, unknown>>();

    // Foreign keys from each user table to another user table, resolved to the parent's column.
    const parentsOf = new Map<string, { parent: string; col: string; parentCol: string }[]>();
    for (const t of tables) {
      const cfg = pgCore.getTableConfig(t.table as never);
      const links: { parent: string; col: string; parentCol: string }[] = [];
      for (const fk of cfg.foreignKeys) {
        const ref = fk.reference();
        const parent = pgCore.getTableConfig(ref.foreignTable as never).name;
        ref.columns.forEach((c, i) => {
          links.push({ parent, col: c.name, parentCol: ref.foreignColumns[i]!.name });
        });
      }
      parentsOf.set(t.name, links);
    }

    const pending = [...tables];
    while (pending.length) {
      const idx = pending.findIndex((t) =>
        (parentsOf.get(t.name) ?? []).every((l) => l.parent === t.name || seeded.has(l.parent) || !names.has(l.parent)),
      );
      if (idx < 0) throw new Error(`cycle among user tables: ${pending.map((t) => t.name).join(", ")}`);
      const [t] = pending.splice(idx, 1);
      const links = new Map((parentsOf.get(t!.name) ?? []).map((l) => [l.col, l]));

      const values: Record<string, unknown> = {};
      for (const c of t!.cols) {
        if (t!.name === USERS_TABLE && c.name === "id") { values[c.name] = userId; continue; }
        if (USER_ID_COLUMNS.has(c.name)) { values[c.name] = userId; continue; }
        const link = links.get(c.name);
        // Keys with a database default are generated here, so a child row can name its parent.
        if (c.primary && c.hasDefault) { values[c.name] = randomUUID(); continue; }
        // Only required links are filled. A nullable link is left empty on purpose: a report
        // whose scan is null is not reached by the cascade from scans, so it must be deleted by name.
        if (link && c.notNull && seeded.has(link.parent)) { values[c.name] = seeded.get(link.parent)![link.parentCol]; continue; }
        if (!c.notNull || c.hasDefault) continue;
        values[c.name] = placeholder(c);
      }
      seeded.set(t!.name, values);

      const cols = Object.keys(values);
      const params = cols.map((_, i) => `$${i + 1}`);
      await dbMod.pool.query(
        `INSERT INTO "${t!.name}" (${cols.map((c) => `"${c}"`).join(", ")}) VALUES (${params.join(", ")})`,
        cols.map((c) => serialise(values[c])),
      );
    }

    // Sessions have no user column: the user id lives inside sess.
    await dbMod.pool.query(
      `INSERT INTO sessions (sid, sess, expire) VALUES ($1, $2::jsonb, $3)`,
      [`${userId}-session`, JSON.stringify({ user: { id: userId } }), new Date(Date.now() + DAY)],
    );
  }

  function placeholder(c: { columnType: string; enumValues?: string[] | readonly string[] }): unknown {
    switch (c.columnType) {
      case "PgUUID": return randomUUID();
      case "PgTimestamp":
      case "PgTimestampString": return new Date(Date.now() + DAY);
      case "PgBoolean": return false;
      case "PgJsonb":
      case "PgJson": return {};
      case "PgInteger":
      case "PgSmallInt":
      case "PgBigInt53":
      case "PgNumeric": return 0;
      default:
        return c.enumValues?.[0] ?? `seed-${randomUUID()}`;
    }
  }

  function serialise(v: unknown): unknown {
    return v !== null && typeof v === "object" && !(v instanceof Date) ? JSON.stringify(v) : v;
  }

  /** Rows that still reference `userId`, across every user table and sessions. */
  async function remainingFor(userId: string): Promise<Record<string, number>> {
    const counts: Record<string, number> = {};
    for (const t of userTables()) {
      const col = t.name === USERS_TABLE ? "id" : t.cols.find((c) => USER_ID_COLUMNS.has(c.name))!.name;
      const r = await dbMod.pool.query(`SELECT count(*)::int AS n FROM "${t.name}" WHERE "${col}" = $1`, [userId]);
      counts[t.name] = r.rows[0].n;
    }
    const s = await dbMod.pool.query(`SELECT count(*)::int AS n FROM sessions WHERE sess->'user'->>'id' = $1`, [userId]);
    counts["sessions"] = s.rows[0].n;
    return counts;
  }

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    ({ registerAccountDelete } = await import("./accountDelete"));
    pgCore = await import("drizzle-orm/pg-core");
    drizzleMod = await import("drizzle-orm");
  }, 60_000);

  afterAll(async () => {
    if (dbMod) {
      await dbMod.pool?.end?.();
    }
  });

  it("seeds a row in every user table, then leaves none for the deleted account", async () => {
    // Seeded first: the derived list and the seeded list must be the same tables.
    const derived = userTables().map((t) => t.name).sort();
    expect(derived).toContain("scans");
    expect(derived).toContain("reports");
    expect(derived).toContain("report_badges");
    expect(derived).toContain("pending_registrations");

    await seedAccount(alice);
    await seedAccount(bob);

    const before = await remainingFor(alice);
    for (const name of derived) {
      expect(before[name], `${name} should hold a seeded row for the account`).toBeGreaterThan(0);
    }
    expect(before["sessions"]).toBeGreaterThan(0);

    const bobBefore = await remainingFor(bob);

    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      // Stands in for authMiddleware: the account has no email, so no emailed code is needed.
      const r = req as unknown as Record<string, unknown>;
      r["user"] = { id: alice, email: null, firstName: null, lastName: null, profileImageUrl: null };
      r["isAuthenticated"] = function (this: { user?: unknown }) { return this.user != null; };
      r["log"] = { info() {}, warn() {}, error() {} };
      next();
    });
    const router = express.Router();
    registerAccountDelete(router);
    app.use("/api", router);

    const res = await request(app).delete("/api/account");
    expect(res.status, JSON.stringify(res.body)).toBe(200);

    const after = await remainingFor(alice);
    expect(Object.entries(after).filter(([, n]) => n !== 0)).toEqual([]);

    // The other account is untouched.
    expect(await remainingFor(bob)).toEqual(bobBefore);
  }, 60_000);
});

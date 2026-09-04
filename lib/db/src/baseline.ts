/**
 * Marks already-applied migrations as applied, without executing them.
 *
 * Only needed once, and only on a database whose schema was built by
 * `drizzle-kit push` before migrations existed. Such a database already has
 * every table that migration 0000 creates, so running the migrator against it
 * would fail on "relation already exists" — the schema is right, the
 * bookkeeping is missing.
 *
 * This writes exactly what the migrator itself would have written: the same
 * schema, table, hash (sha256 of the raw .sql file) and created_at
 * (the journal's `when`), read from drizzle-orm's own migrator so the two
 * cannot drift.
 *
 *   DATABASE_URL=... pnpm --filter @workspace/db run db:baseline
 *
 * Run it only when the live schema genuinely matches the current schema files.
 * On a fresh database, skip this entirely and just run db:migrate.
 */

import { Pool } from "pg";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MIGRATIONS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "migrations",
);

interface JournalEntry {
  tag: string;
  when: number;
}

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];
  if (!url) throw new Error("DATABASE_URL must be set");

  const journalPath = path.join(MIGRATIONS_DIR, "meta", "_journal.json");
  if (!fs.existsSync(journalPath)) {
    throw new Error(`No journal at ${journalPath} — nothing to baseline`);
  }
  const journal = JSON.parse(fs.readFileSync(journalPath, "utf8")) as {
    entries: JournalEntry[];
  };

  const pool = new Pool({ connectionString: url, max: 1 });
  const client = await pool.connect();
  try {
    await client.query(`CREATE SCHEMA IF NOT EXISTS "drizzle"`);
    await client.query(`
      CREATE TABLE IF NOT EXISTS "drizzle"."__drizzle_migrations" (
        id SERIAL PRIMARY KEY,
        hash text NOT NULL,
        created_at bigint
      )
    `);

    const { rows: existing } = await client.query<{ hash: string }>(
      `SELECT hash FROM "drizzle"."__drizzle_migrations"`,
    );
    const already = new Set(existing.map((r) => r.hash));

    let marked = 0;
    for (const entry of journal.entries) {
      const sqlPath = path.join(MIGRATIONS_DIR, `${entry.tag}.sql`);
      const contents = fs.readFileSync(sqlPath).toString();
      const hash = crypto.createHash("sha256").update(contents).digest("hex");

      if (already.has(hash)) {
        console.log(`already recorded: ${entry.tag}`);
        continue;
      }
      await client.query(
        `INSERT INTO "drizzle"."__drizzle_migrations" ("hash", "created_at") VALUES ($1, $2)`,
        [hash, entry.when],
      );
      console.log(`baselined: ${entry.tag}`);
      marked += 1;
    }

    console.log(
      marked === 0
        ? "Nothing to do — every migration was already recorded."
        : `Recorded ${marked} migration(s) as applied. Future changes go through db:migrate.`,
    );
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error("Baseline failed:", err);
  process.exit(1);
});

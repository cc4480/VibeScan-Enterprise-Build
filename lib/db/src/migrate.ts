/**
 * Applies committed migrations, in order, exactly once each.
 *
 * This replaces `drizzle-kit push` as the way schema reaches a real database.
 * `push` compares the schema files against whatever is live and applies the
 * difference it infers — including dropping a column it believes was removed —
 * with no reviewable artifact and no way back. That is a reasonable tool on a
 * laptop and the wrong one for a database holding customer reports.
 *
 * Drizzle records what it has run in a migrations table, so this is safe to run
 * on every deploy: applying nothing is the normal outcome.
 *
 * ── Adopting this on a database that was built with `push` ──
 * Such a database already has the tables that migration 0000 creates, so a
 * first run would fail on "relation already exists". Baseline it once by
 * marking 0000 as applied without executing it:
 *
 *   pnpm --filter @workspace/db run db:baseline
 *
 * Only do that when the live schema genuinely matches the current schema files.
 */

import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MIGRATIONS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "migrations",
);

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];
  if (!url) throw new Error("DATABASE_URL must be set");

  const pool = new Pool({ connectionString: url, max: 1 });
  try {
    const db = drizzle(pool);
    console.log(`Applying migrations from ${MIGRATIONS_DIR}`);
    await migrate(db, { migrationsFolder: MIGRATIONS_DIR });
    console.log("Migrations up to date");
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error("Migration failed:", err);
  process.exit(1);
});

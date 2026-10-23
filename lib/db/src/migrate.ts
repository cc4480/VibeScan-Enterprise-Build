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
 * ── This is no longer the primary way migrations reach production ──
 * Both service entrypoints call migrateToLatest() on boot, so a deploy migrates
 * itself. This CLI stays for the cases where running it by hand is the point:
 * migrating a database before anything is deployed against it, applying a
 * migration from a laptop during development, or checking that a database is
 * current without restarting a service.
 *
 * Both paths call the SAME function, deliberately — a boot path and a CLI path
 * that could drift is how a database ends up in a state neither expects.
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

import { migrateToLatest } from "./bootMigrate.js";

async function main(): Promise<void> {
  const url = process.env["DATABASE_URL"];
  if (!url) throw new Error("DATABASE_URL must be set");
  await migrateToLatest(url, (msg) => console.log(msg));
}

main().catch((err: unknown) => {
  console.error("Migration failed:", err);
  process.exit(1);
});

/**
 * Applies committed migrations, with a lock, from wherever it is called.
 *
 * Shared by the `db:migrate` CLI and by both service entrypoints, which run it
 * on boot. One implementation on purpose: a boot path and a CLI path that could
 * drift is how a database ends up in a state neither one expects.
 *
 * ── Why this exists at all ──
 * Until now migrations reached production only by hand, and the documented
 * procedure (deploy/railway/NOTES.md) was to create a TCP proxy exposing
 * Postgres to the internet, migrate through it, and remember to delete the
 * proxy afterwards. DATABASE_URL resolves to postgres.railway.internal, which
 * only exists inside Railway's network, so `railway run` fails with ENOTFOUND;
 * and the runtime image carried no migrations to apply for itself.
 *
 * That procedure had to be performed correctly, by a person, before every
 * schema-dependent deploy — and skipping it is silent until the first request
 * touches the missing table. Both services have already booted against a
 * database missing `eol_cache` and logged it at length. Applying migrations on
 * boot removes the step rather than documenting it better.
 *
 * ── Why the advisory lock ──
 * drizzle's migrate() takes NO lock. It reads the newest row in its ledger,
 * then applies everything newer in one transaction. Two processes starting
 * together therefore both read the same "last applied" value, both decide the
 * same migration is pending, and the loser fails on "relation already exists"
 * — aborting its transaction and killing its boot.
 *
 * This is not theoretical here: `web` and `secscan` are separate services
 * sharing one database, deployed from one image, and they start at the same
 * time. The lock serialises them; whoever waits then finds the ledger already
 * current and applies nothing.
 *
 * It is a session-level lock on its own connection, held across migrate() and
 * released in a finally. A crashed process drops its connection and Postgres
 * releases the lock with it, so a failed boot cannot wedge the next one.
 */

import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { Pool } from "pg";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Arbitrary fixed key. Its only requirement is being the SAME constant in every
 * process, so they contend on one lock. Advisory locks live in a namespace
 * shared with anything else using this database — pg-boss included — so it is
 * deliberately not a small round number that something else might also pick.
 */
export const MIGRATION_ADVISORY_LOCK_KEY = 8_147_390_215_674_113n;

/**
 * How long to wait for another process's migration before giving up.
 *
 * Without a bound, a peer that hangs mid-migration hangs every other boot
 * behind it indefinitely, and the service looks alive-but-silent rather than
 * failed. Timing out crashes this process instead, which a supervisor restarts
 * — by which time the peer has usually finished and the retry applies nothing.
 */
const LOCK_TIMEOUT_MS = Number(process.env["MIGRATION_LOCK_TIMEOUT_MS"]) || 60_000;

/**
 * Find the committed migrations.
 *
 * Resolved from the WORKING DIRECTORY rather than from this module's own path,
 * because in production this file does not exist as a file: esbuild bundles it
 * into artifacts/api-server/dist/index.mjs, where `import.meta.url` points at
 * the bundle and "../migrations" is a directory that was never there. The
 * Dockerfile copies the migrations to /app/lib/db/migrations and WORKDIR is
 * /app, so the cwd-relative candidate is the one that resolves in the image.
 *
 * The import.meta.url candidate is kept last for the CLI, which runs from
 * source through tsx where it is correct.
 */
export function migrationsDirCandidates(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): string[] {
  return [
    env["MIGRATIONS_DIR"],
    path.join(cwd, "lib", "db", "migrations"),
    path.join(cwd, "migrations"),
    path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "migrations"),
  ]
    .filter((p): p is string => !!p)
    // Deduped because the list is printed verbatim when nothing is found, and
    // the same path appearing twice makes the diagnostic read as though two
    // different locations were checked. In the bundle, the cwd- and
    // module-relative candidates often resolve to the same directory.
    .filter((p, i, all) => all.indexOf(p) === i);
}

export function resolveMigrationsDir(candidates: string[] = migrationsDirCandidates()): string {
  for (const dir of candidates) {
    // Check for the journal, not just the directory: an empty `migrations/`
    // left behind by a bad COPY would otherwise look like a valid folder with
    // nothing pending, and the process would boot cleanly against a database
    // it never migrated. That is the failure this whole change exists to stop,
    // so it must not be reintroduced by the path lookup.
    if (fs.existsSync(path.join(dir, "meta", "_journal.json"))) return dir;
  }

  throw new Error(
    `Could not find the migrations folder — the schema cannot be applied. Tried:\n  ${candidates.join("\n  ")}`,
  );
}

export interface MigrateResult {
  migrationsDir: string;
  /** Whether this process held the lock and ran migrate, vs. waited and found it done. */
  applied: boolean;
}

/**
 * Bring the database to the latest committed migration.
 *
 * Throws on failure, and callers must NOT swallow it: a process that cannot
 * establish its schema has to fail its deploy rather than start and throw on
 * every request that touches a missing table.
 */
export async function migrateToLatest(
  connectionString: string,
  log: (msg: string) => void = () => {},
): Promise<MigrateResult> {
  const migrationsDir = resolveMigrationsDir();
  const pool = new Pool({ connectionString, max: 2 });

  try {
    const lockClient = await pool.connect();
    try {
      // lock_timeout bounds the WAIT for the advisory lock below. Set on this
      // connection only, so it cannot affect anything else.
      await lockClient.query(`SET lock_timeout = ${Math.max(1000, LOCK_TIMEOUT_MS)}`);
      try {
        await lockClient.query("SELECT pg_advisory_lock($1)", [MIGRATION_ADVISORY_LOCK_KEY.toString()]);
      } catch (err) {
        throw new Error(
          `Timed out waiting ${LOCK_TIMEOUT_MS}ms for another process to finish migrating. ` +
            `If no other deploy is running, a previous migration may have failed mid-flight — ` +
            `check the database before restarting. Cause: ${(err as Error).message}`,
        );
      }

      log(`Applying migrations from ${migrationsDir}`);
      await migrate(drizzle(pool), { migrationsFolder: migrationsDir });
      log("Migrations up to date");
      return { migrationsDir, applied: true };
    } finally {
      // Best-effort: if the connection already died, the lock died with it.
      try {
        await lockClient.query("SELECT pg_advisory_unlock($1)", [MIGRATION_ADVISORY_LOCK_KEY.toString()]);
      } catch {
        /* connection gone — Postgres released the lock already */
      }
      lockClient.release();
    }
  } finally {
    await pool.end();
  }
}

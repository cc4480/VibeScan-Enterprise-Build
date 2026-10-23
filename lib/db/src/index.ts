import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

/**
 * Connection ceiling per process, not per scan.
 *
 * A connection is held for the duration of a query, not the duration of a
 * scan — a scan makes a few dozen short queries across roughly a minute — so
 * one pool serves many more concurrent scans than its size suggests. What the
 * pool has to survive is the bursts: several scans finishing at once, each
 * writing a report and updating its rows.
 *
 * It was previously unset, which meant node-postgres's default of 10. That is
 * fine for one worker at a concurrency of 8 and stops being fine quietly:
 * running more replicas, or raising SCAN_WORKER_CONCURRENCY to drain a queue
 * faster, adds load here with no error to read — requests wait for a
 * connection instead of failing, so the symptom is a slow scan, not a broken
 * one. Set it deliberately so the ceiling is a decision rather than a default.
 *
 * Budget it against the server's max_connections, which every process shares:
 *
 *   (web replicas + worker replicas) x (DB_POOL_MAX + pg-boss max)  <  max_connections
 *
 * pg-boss keeps its own pool of 3 (see api-server lib/queue.ts), so each
 * process costs DB_POOL_MAX + 3. Postgres defaults to 100 connections total
 * and reserves a few for superusers.
 */
const DB_POOL_MAX = Math.max(2, Number(process.env["DB_POOL_MAX"]) || 10);

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: DB_POOL_MAX,
  // Hand a connection back after 30s idle so a replica that has finished a
  // burst stops holding connections other replicas could be using.
  idleTimeoutMillis: 30_000,
  // Fail loudly rather than hanging forever when the pool is genuinely
  // exhausted — a timeout names the problem, an indefinite wait does not.
  connectionTimeoutMillis: 10_000,
});
// An idle client can error (the server restarts, a proxy drops the socket). Without a listener that
// "error" event is unhandled and takes the whole process down; with one, the pool discards the
// client and the next query opens a fresh connection.
pool.on("error", (err) => {
  console.error("Postgres pool: idle client error (connection discarded)", err.message);
});

export const db = drizzle(pool, { schema });

export * from "./schema";

// Applying migrations is part of starting up, so it ships with the database
// package rather than living only in a CLI script. See bootMigrate.ts.
export { migrateToLatest, resolveMigrationsDir, migrationsDirCandidates, MIGRATION_ADVISORY_LOCK_KEY } from "./bootMigrate.js";

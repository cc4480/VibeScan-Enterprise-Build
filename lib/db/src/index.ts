import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const db = drizzle(pool, { schema });

export * from "./schema";

// Applying migrations is part of starting up, so it ships with the database
// package rather than living only in a CLI script. See bootMigrate.ts.
export { migrateToLatest, resolveMigrationsDir, migrationsDirCandidates, MIGRATION_ADVISORY_LOCK_KEY } from "./bootMigrate.js";

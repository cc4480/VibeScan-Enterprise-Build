import { PgBoss } from "pg-boss";
import { logger } from "./logger";

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL must be set");
}

export const SCAN_QUEUE = "scan-job";

let boss: PgBoss | null = null;
let startPromise: Promise<PgBoss> | null = null;

export async function getBoss(): Promise<PgBoss> {
  if (boss) return boss;
  if (startPromise) return startPromise;

  startPromise = (async () => {
    const instance = new PgBoss({
      connectionString: DATABASE_URL!,
      // Small pool — production Postgres has strict connection limits.
      max: 3,
      connectionTimeoutMillis: 10_000,
      // Run maintenance every 20 seconds instead of the default 60.
      // This keeps the pg-boss Timekeeper connection active, preventing it
      // from sitting idle long enough for Replit's production Postgres to
      // drop it (~30–60 s idle timeout on hosted providers).
      monitorIntervalSeconds: 20,
      maintenanceIntervalSeconds: 20,
    });

    // ⚠️  CRITICAL: handle pg-boss internal error events.
    // pg-boss emits 'error' on its instance when a maintenance connection
    // drops (e.g. Timekeeper connection timeout).  Without this handler Node.js
    // treats it as an uncaught error and kills the entire process — which is
    // exactly why scans get stuck at "queued" in production.
    instance.on("error", (err: unknown) => {
      logger.warn({ err }, "pg-boss internal error (non-fatal) — pool will reconnect automatically");
    });

    await instance.start();
    boss = instance;
    return boss;
  })().catch((err) => {
    // Reset so the next caller can retry initialisation
    startPromise = null;
    throw err;
  });

  return startPromise;
}

export interface ScanJobData {
  scanId: string;
  userId: string;
  targetUrl: string;
  tier: string;
}

export async function enqueueScan(data: ScanJobData): Promise<string | null> {
  const b = await getBoss();
  await b.createQueue(SCAN_QUEUE, { retryLimit: 2, retryDelay: 30, expireInSeconds: 7200 });
  return b.send(SCAN_QUEUE, data);
}

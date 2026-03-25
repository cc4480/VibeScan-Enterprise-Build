import { PgBoss } from "pg-boss";

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
    const instance = new PgBoss(DATABASE_URL!);
    await instance.start();
    boss = instance;
    return boss;
  })();

  return startPromise;
}

export interface ScanJobData {
  scanId: string;
  userId: string;
  targetUrl: string;
  tier: string;
}

export async function ensureQueue(): Promise<void> {
  const b = await getBoss();
  await b.createQueue(SCAN_QUEUE, {
    retryLimit: 2,
    retryDelay: 30,
    expireInSeconds: 7200,
  });
}

export async function enqueueScan(data: ScanJobData): Promise<string | null> {
  const b = await getBoss();
  // Ensure queue exists (idempotent) before sending
  await b.createQueue(SCAN_QUEUE, { retryLimit: 2, retryDelay: 30, expireInSeconds: 7200 });
  return b.send(SCAN_QUEUE, data);
}

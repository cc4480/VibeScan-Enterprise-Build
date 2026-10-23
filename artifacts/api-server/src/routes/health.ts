import { Router, type IRouter } from "express";
import { HealthCheckResponse } from "@workspace/api-zod";
import { db, scansTable, monitorPulseChecksTable, monitorSubscriptionsTable } from "@workspace/db";
import { and, count, eq, lt, max, sql } from "drizzle-orm";
import { rateLimitMiddleware } from "../lib/rateLimit";

const router: IRouter = Router();

/**
 * Shallow on purpose: the container's HEALTHCHECK (Dockerfile) calls this, and
 * a database blip must not get the web service restarted. It only says the web
 * process answers. For "is the product actually working", see /healthz/deep.
 */
router.get("/healthz", (_req, res) => {
  const data = HealthCheckResponse.parse({ status: "ok" });
  res.json(data);
});

/** A queued scan no worker has picked up for this long means the worker is down or stuck. */
export const QUEUE_STALL_MS = 10 * 60 * 1000;
/** The worker's pulse job runs hourly; allow half an hour of slack. */
export const PULSE_STALE_MS = 90 * 60 * 1000;

export interface DeepHealthInput {
  dbOk: boolean;
  /** Scans queued longer than QUEUE_STALL_MS. */
  stalledScans: number;
  activeMonitors: number;
  lastPulseAt: Date | null;
  now: Date;
}

export interface DeepHealth {
  ok: boolean;
  checks: { database: "ok" | "down"; worker: "ok" | "stalled" | "unknown" };
  problems: string[];
}

/**
 * What an external uptime monitor should alert on. Pure, so the rule is tested
 * without a database. Exported for tests.
 *
 * The worker has no public address, so it is judged by its effects: queued
 * scans nobody picked up, and the hourly monitor pulse going quiet while sites
 * are being monitored. With no active monitors the pulse says nothing, so only
 * the queue counts.
 */
export function assessDeepHealth(input: DeepHealthInput): DeepHealth {
  const problems: string[] = [];
  if (!input.dbOk) {
    problems.push("Database is not answering.");
    return { ok: false, checks: { database: "down", worker: "unknown" }, problems };
  }

  let worker: DeepHealth["checks"]["worker"] = "ok";
  if (input.stalledScans > 0) {
    worker = "stalled";
    problems.push(
      `${input.stalledScans} scan${input.stalledScans === 1 ? " has" : "s have"} waited over ${QUEUE_STALL_MS / 60000} minutes for the worker.`,
    );
  }
  if (input.activeMonitors > 0) {
    const age = input.lastPulseAt ? input.now.getTime() - input.lastPulseAt.getTime() : Infinity;
    if (age > PULSE_STALE_MS) {
      worker = "stalled";
      problems.push(
        input.lastPulseAt
          ? `No hourly monitor check for ${Math.round(age / 60000)} minutes.`
          : "Sites are monitored but no hourly check has ever run.",
      );
    }
  }

  return { ok: problems.length === 0, checks: { database: "ok", worker }, problems };
}

// Each call runs three small queries; an uptime monitor calls it every few
// minutes, so this only stops someone using it to load the database.
const deepHealthRateLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60_000, max: 20, label: "minute" }],
  name: "healthz-deep",
});

/**
 * For external uptime monitoring: 200 when the database answers and the scan
 * worker is doing its job, 503 (with what is wrong) otherwise. Says nothing
 * about any user or any data, only whether the product works.
 */
router.get("/healthz/deep", deepHealthRateLimit, async (_req, res) => {
  const now = new Date();
  let input: DeepHealthInput = { dbOk: false, stalledScans: 0, activeMonitors: 0, lastPulseAt: null, now };

  try {
    const timeout = new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000));
    const probe = (async () => {
      await db.execute(sql`select 1`);
      const [[stalled], [monitors], [pulse]] = await Promise.all([
        db
          .select({ n: count() })
          .from(scansTable)
          .where(and(eq(scansTable.status, "queued"), lt(scansTable.startedAt, new Date(now.getTime() - QUEUE_STALL_MS)))),
        db.select({ n: count() }).from(monitorSubscriptionsTable).where(eq(monitorSubscriptionsTable.status, "active")),
        db.select({ at: max(monitorPulseChecksTable.checkedAt) }).from(monitorPulseChecksTable),
      ]);
      return {
        dbOk: true,
        stalledScans: Number(stalled?.n ?? 0),
        activeMonitors: Number(monitors?.n ?? 0),
        lastPulseAt: pulse?.at ? new Date(pulse.at) : null,
        now,
      };
    })();
    input = await Promise.race([probe, timeout]);
  } catch {
    // dbOk stays false.
  }

  const health = assessDeepHealth(input);
  res
    .status(health.ok ? 200 : 503)
    .setHeader("Cache-Control", "no-store")
    .json({ status: health.ok ? "ok" : "degraded", ...health, checkedAt: now.toISOString() });
});

export default router;

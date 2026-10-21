import { type Request, type Response, type NextFunction } from "express";
import { db, reportsTable } from "@workspace/db";
import { eq, and, desc } from "drizzle-orm";
import { sameSite } from "../lib/urlKey";
import { z } from "zod";
import { rateLimitMiddleware, scanRateLimitRules } from "../lib/rateLimit";

/** Pieces shared by the monitor routes: the latest-report lookup, request schema, rate limit and auth guard. */
export const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
export const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

/** Fetch the most recent completed report for a user+URL pair. */
export async function fetchLatestReport(
  userId: string,
  targetUrl: string,
  executor: Pick<typeof db, "select"> = db,
) {
  const [report] = await executor
    .select({
      id: reportsTable.id,
      scannedAt: reportsTable.scannedAt,
      data: reportsTable.data,
    })
    .from(reportsTable)
    .where(and(eq(reportsTable.userId, userId), sameSite(reportsTable.targetUrl, targetUrl)))
    .orderBy(desc(reportsTable.scannedAt))
    .limit(1);
  return report ?? null;
}

// Capped because target_url is btree-indexed (idx_monitor_target), and a value past the
// index's entry limit made the insert fail with a 500 instead of a 400.
export const MONITOR_URL_MAX_LENGTH = 2048;

export const CreateMonitorBody = z.object({
  targetUrl: z.string().max(MONITOR_URL_MAX_LENGTH, "That URL is too long").url("Must be a valid URL"),
  webhookUrl: z.string().max(MONITOR_URL_MAX_LENGTH, "That webhook URL is too long").url().optional(),
});

// A subscription schedules recurring scans, so it draws on the same budget.
// Per user, for the same reason as the scan route: this was IP-keyed, so
// colleagues on one office egress shared a single allowance.
export const monitorRateLimit = rateLimitMiddleware({
  rules: scanRateLimitRules(),
  name: "monitor-subscriptions",
  keyFrom: (req) => (req.isAuthenticated() ? `user:${req.user.id}` : undefined),
});

// Auth first, so an unauthenticated caller cannot spend a real user's budget.
export function requireMonitorAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

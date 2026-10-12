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
export async function fetchLatestReport(userId: string, targetUrl: string) {
  const [report] = await db
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

export const CreateMonitorBody = z.object({
  targetUrl: z.string().url("Must be a valid URL"),
  webhookUrl: z.string().url().optional(),
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

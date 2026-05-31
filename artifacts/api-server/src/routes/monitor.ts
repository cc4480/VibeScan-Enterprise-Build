import { Router, type IRouter } from "express";
import {
  db, monitorSubscriptionsTable, cveAlertsTable, reportsTable,
  monitorScoreHistoryTable, monitorRegressionsTable, certExpiryAlertsTable,
} from "@workspace/db";
import { eq, and, desc, count, sql } from "drizzle-orm";
import { z } from "zod";
import { enqueueScan } from "../lib/queue";
import { scansTable } from "@workspace/db";
import { logger } from "../lib/logger";

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

/** Fetch the most recent completed report for a user+URL pair. */
async function fetchLatestReport(userId: string, targetUrl: string) {
  const [report] = await db
    .select({
      id: reportsTable.id,
      scannedAt: reportsTable.scannedAt,
      data: reportsTable.data,
    })
    .from(reportsTable)
    .where(and(eq(reportsTable.userId, userId), eq(reportsTable.targetUrl, targetUrl)))
    .orderBy(desc(reportsTable.scannedAt))
    .limit(1);
  return report ?? null;
}

const router: IRouter = Router();

const CreateMonitorBody = z.object({
  targetUrl: z.string().url("Must be a valid URL"),
  webhookUrl: z.string().url().optional(),
});

// ── POST /api/monitor/subscriptions ──────────────────────────────────────────
// Create a new monitoring subscription for a URL.
// With DISABLE_PAYMENTS=true this is granted immediately.

router.post("/monitor/subscriptions", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CreateMonitorBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Invalid request" });
    return;
  }

  const { targetUrl, webhookUrl } = parsed.data;
  const paymentsDisabled = process.env.DISABLE_PAYMENTS === "true";

  if (!paymentsDisabled) {
    res.status(503).json({ error: "Subscription payments are not yet configured." });
    return;
  }

  // Check for an existing active subscription for this user+URL
  const [existing] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.userId, req.user.id),
        eq(monitorSubscriptionsTable.targetUrl, targetUrl),
        eq(monitorSubscriptionsTable.status, "active"),
      ),
    );

  if (existing) {
    res.status(409).json({ error: "You already have an active monitor subscription for this URL." });
    return;
  }

  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setFullYear(expiresAt.getFullYear() + 1);

  // Seed from the most recent existing report for this URL so the card
  // immediately shows the last grade/scan date instead of "Never".
  const existingReport = await fetchLatestReport(req.user.id, targetUrl);
  const seedReportId = existingReport?.id ?? null;
  const seedScanAt = existingReport?.scannedAt ?? null;

  const [sub] = await db
    .insert(monitorSubscriptionsTable)
    .values({
      userId: req.user.id,
      userEmail: req.user.email ?? "",
      targetUrl,
      status: "active",
      expiresAt,
      lastReportId: seedReportId,
      lastScanAt: seedScanAt,
      webhookUrl: webhookUrl ?? null,
    })
    .returning();

  // Only enqueue a new scan if there is no recent report (> 7 days old counts as stale).
  const reportAge = existingReport
    ? now.getTime() - new Date(existingReport.scannedAt).getTime()
    : Infinity;
  const needsInitialScan = reportAge > SEVEN_DAYS_MS;

  if (!needsInitialScan) {
    logger.info(
      { subscriptionId: sub.id, existingReportId: seedReportId },
      "Recent report found — skipping initial scan",
    );
    res.status(201).json({ subscription: sub, initialScanId: null });
    return;
  }

  // No recent report — trigger a baseline deep scan.
  try {
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId: req.user.id,
        userEmail: req.user.email ?? "",
        targetUrl,
        tier: "deep",
        status: "paid",
      })
      .returning();

    await enqueueScan({
      scanId: scan.id,
      userId: req.user.id,
      targetUrl,
      tier: "deep",
      monitorSubscriptionId: sub.id,
    });

    await db
      .update(scansTable)
      .set({ status: "queued", startedAt: new Date() })
      .where(eq(scansTable.id, scan.id));

    logger.info({ subscriptionId: sub.id, scanId: scan.id }, "Initial monitor scan queued");

    res.status(201).json({
      subscription: sub,
      initialScanId: scan.id,
    });
  } catch (err) {
    logger.error({ err }, "Failed to enqueue initial monitor scan");
    res.status(201).json({ subscription: sub, initialScanId: null });
  }
});

// ── GET /api/monitor/subscriptions ───────────────────────────────────────────
// List all monitor subscriptions for the authenticated user.

router.get("/monitor/subscriptions", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subs = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.userId, req.user.id))
    .orderBy(desc(monitorSubscriptionsTable.createdAt));

  // Attach latest report info and alert count to each subscription
  const enriched = await Promise.all(
    subs.map(async (sub) => {
      // Resolve the report: prefer lastReportId, fall back to most-recent report for the URL
      let resolvedReport: { id: string; scannedAt: Date; data: unknown } | null = null;

      if (sub.lastReportId) {
        const [r] = await db
          .select({ id: reportsTable.id, scannedAt: reportsTable.scannedAt, data: reportsTable.data })
          .from(reportsTable)
          .where(eq(reportsTable.id, sub.lastReportId));
        resolvedReport = r ?? null;
      }

      // Fallback: look up the most recent report for this user+URL
      if (!resolvedReport) {
        resolvedReport = await fetchLatestReport(sub.userId, sub.targetUrl);
        // If we found one via fallback, backfill the subscription row so future
        // calls use the fast path.
        if (resolvedReport) {
          await db
            .update(monitorSubscriptionsTable)
            .set({
              lastReportId: resolvedReport.id,
              lastScanAt: resolvedReport.scannedAt,
            })
            .where(eq(monitorSubscriptionsTable.id, sub.id));
        }
      }

      let lastReport: { id: string; grade: string | null; riskScore: number | null } | null = null;
      if (resolvedReport) {
        const data = resolvedReport.data as { summary?: { grade?: string; riskScore?: number } };
        lastReport = {
          id: resolvedReport.id,
          grade: data.summary?.grade ?? null,
          riskScore: data.summary?.riskScore ?? null,
        };
      }

      // Count CVE alerts
      const [{ value: alertCount }] = await db
        .select({ value: count() })
        .from(cveAlertsTable)
        .where(eq(cveAlertsTable.subscriptionId, sub.id));

      // Count regressions from the most recent scan only
      const [latestHistory] = await db
        .select({ scanId: monitorScoreHistoryTable.scanId })
        .from(monitorScoreHistoryTable)
        .where(eq(monitorScoreHistoryTable.subscriptionId, sub.id))
        .orderBy(desc(monitorScoreHistoryTable.scannedAt))
        .limit(1);

      let regressionCount = 0;
      if (latestHistory?.scanId) {
        const [{ value }] = await db
          .select({ value: count() })
          .from(monitorRegressionsTable)
          .where(
            and(
              eq(monitorRegressionsTable.subscriptionId, sub.id),
              eq(monitorRegressionsTable.scanId, latestHistory.scanId),
            ),
          );
        regressionCount = Number(value);
      }

      // Check for cert expiry from most recent cert_expiry_alerts
      const [latestCertAlert] = await db
        .select({ daysRemaining: certExpiryAlertsTable.daysRemaining })
        .from(certExpiryAlertsTable)
        .where(eq(certExpiryAlertsTable.subscriptionId, sub.id))
        .orderBy(desc(certExpiryAlertsTable.sentAt))
        .limit(1);

      const certExpiryDays = latestCertAlert?.daysRemaining ?? null;

      // Use the resolved scanAt so the card shows the correct date even before
      // the subscription row was backfilled.
      const lastScanAt = sub.lastScanAt ?? resolvedReport?.scannedAt ?? null;

      return {
        ...sub,
        lastScanAt,
        lastReport,
        alertCount,
        regressionCount: Number(regressionCount),
        certExpiryDays,
      };
    }),
  );

  res.json(enriched);
});

// ── DELETE /api/monitor/subscriptions/:id ────────────────────────────────────
// Cancel a monitor subscription.

router.delete("/monitor/subscriptions/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  await db
    .update(monitorSubscriptionsTable)
    .set({ status: "cancelled" })
    .where(eq(monitorSubscriptionsTable.id, subId));

  res.json({ success: true });
});

// ── GET /api/monitor/subscriptions/:id/alerts ────────────────────────────────
// List CVE alerts for a subscription.

router.get("/monitor/subscriptions/:id/alerts", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  // Order by EPSS × severity_weight descending (highest exploit probability × impact first)
  const alerts = await db
    .select()
    .from(cveAlertsTable)
    .where(eq(cveAlertsTable.subscriptionId, subId))
    .orderBy(
      sql`COALESCE(${cveAlertsTable.epssScore}, 0) * CASE ${cveAlertsTable.severity}
        WHEN 'CRITICAL' THEN 4
        WHEN 'HIGH' THEN 3
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 1
        ELSE 1 END DESC`,
      desc(cveAlertsTable.detectedAt),
    );

  res.json(alerts);
});

// ── GET /api/monitor/subscriptions/:id/history ────────────────────────────────
// Return the last 30 score history points for a subscription.

router.get("/monitor/subscriptions/:id/history", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select({ id: monitorSubscriptionsTable.id })
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  const history = await db
    .select()
    .from(monitorScoreHistoryTable)
    .where(eq(monitorScoreHistoryTable.subscriptionId, subId))
    .orderBy(desc(monitorScoreHistoryTable.scannedAt))
    .limit(30);

  res.json(history.reverse()); // oldest first for charting
});

// ── GET /api/monitor/subscriptions/:id/regressions ───────────────────────────
// Return regressions from the most recent completed monitor scan.

router.get("/monitor/subscriptions/:id/regressions", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select({ id: monitorSubscriptionsTable.id })
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  // Find the most recent scan tracked in score history
  const [latestHistory] = await db
    .select({ scanId: monitorScoreHistoryTable.scanId })
    .from(monitorScoreHistoryTable)
    .where(eq(monitorScoreHistoryTable.subscriptionId, subId))
    .orderBy(desc(monitorScoreHistoryTable.scannedAt))
    .limit(1);

  if (!latestHistory?.scanId) {
    res.json([]);
    return;
  }

  const regressions = await db
    .select()
    .from(monitorRegressionsTable)
    .where(
      and(
        eq(monitorRegressionsTable.subscriptionId, subId),
        eq(monitorRegressionsTable.scanId, latestHistory.scanId),
      ),
    )
    .orderBy(desc(monitorRegressionsTable.detectedAt));

  res.json(regressions);
});

// ── POST /api/monitor/subscriptions/:id/scan ─────────────────────────────────
// Immediately enqueue a manual deep scan for a subscription.

router.post("/monitor/subscriptions/:id/scan", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  if (sub.status !== "active") {
    res.status(400).json({ error: "Subscription is not active" });
    return;
  }

  try {
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId: req.user.id,
        userEmail: req.user.email ?? "",
        targetUrl: sub.targetUrl,
        tier: "deep",
        status: "paid",
      })
      .returning();

    await enqueueScan({
      scanId: scan.id,
      userId: req.user.id,
      targetUrl: sub.targetUrl,
      tier: "deep",
      monitorSubscriptionId: sub.id,
    });

    await db
      .update(scansTable)
      .set({ status: "queued", startedAt: new Date() })
      .where(eq(scansTable.id, scan.id));

    logger.info({ subscriptionId: sub.id, scanId: scan.id }, "Manual monitor scan queued");

    res.json({ scanId: scan.id });
  } catch (err) {
    logger.error({ err }, "Failed to enqueue manual monitor scan");
    res.status(500).json({ error: "Failed to enqueue scan" });
  }
});

export default router;

import { type IRouter } from "express";
import { db, monitorSubscriptionsTable, cveAlertsTable, reportsTable, monitorScoreHistoryTable, monitorRegressionsTable } from "@workspace/db";
import { eq, and, desc, count, sql } from "drizzle-orm";
import { sameSite } from "../lib/urlKey";
import { splitScanNotes } from "../lib/scanNotes";

/** Per-subscription history: scans, alerts, score history and regressions. */



export function registerMonitorHistory(router: IRouter): void {

  // ── GET /api/monitor/subscriptions/:id/history ───────────────────────────────
  // Return all completed reports for the subscription's URL, newest first.

  router.get("/monitor/subscriptions/:id/history", async (req, res): Promise<void> => {
    if (!req.isAuthenticated()) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const [sub] = await db
      .select()
      .from(monitorSubscriptionsTable)
      .where(
        and(
          eq(monitorSubscriptionsTable.id, req.params.id),
          eq(monitorSubscriptionsTable.userId, req.user.id),
        ),
      );

    if (!sub) {
      res.status(404).json({ error: "Subscription not found" });
      return;
    }

    const reports = await db
      .select({
        id: reportsTable.id,
        scanId: reportsTable.scanId,
        scannedAt: reportsTable.scannedAt,
        tier: reportsTable.tier,
        data: reportsTable.data,
      })
      .from(reportsTable)
      .where(
        and(
          eq(reportsTable.userId, req.user.id),
          sameSite(reportsTable.targetUrl, sub.targetUrl),
        ),
      )
      .orderBy(desc(reportsTable.scannedAt))
      .limit(20);

    const history = reports.map((r) => {
      const data = r.data as {
        summary?: { grade?: string; riskScore?: number; totalVulnerabilities?: number };
        vulnerabilities?: unknown[];
      };
      return {
        id: r.id,
        scanId: r.scanId,
        scannedAt: r.scannedAt,
        tier: r.tier,
        grade: data.summary?.grade ?? null,
        riskScore: data.summary?.riskScore ?? null,
        // The stored field is totalVulnerabilities (see worker.ts's reportData) —
        // this read `vulnCount`, a name that has never existed on a report, so
        // every history entry ever returned this null regardless of the real count.
        // Counted from the list when there is one, without the scan's notes, so a scan saved before
        // notes were left out of its stored total sits on the same scale as one saved after.
        vulnCount: Array.isArray(data.vulnerabilities)
          ? splitScanNotes(data.vulnerabilities).findings.length
          : (data.summary?.totalVulnerabilities ?? null),
      };
    });

    res.json(history);
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

  // ── GET /api/monitor/subscriptions/:id/score-history ──────────────────────────
  // Return the last 30 score history points for a subscription (for charting).

  router.get("/monitor/subscriptions/:id/score-history", async (req, res): Promise<void> => {
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

    // Join with reports to include reportId so the frontend can link to each report
    const history = await db
      .select({
        id: monitorScoreHistoryTable.id,
        subscriptionId: monitorScoreHistoryTable.subscriptionId,
        scanId: monitorScoreHistoryTable.scanId,
        grade: monitorScoreHistoryTable.grade,
        riskScore: monitorScoreHistoryTable.riskScore,
        criticalCount: monitorScoreHistoryTable.criticalCount,
        highCount: monitorScoreHistoryTable.highCount,
        scannedAt: monitorScoreHistoryTable.scannedAt,
        reportId: reportsTable.id,
      })
      .from(monitorScoreHistoryTable)
      .leftJoin(reportsTable, eq(reportsTable.scanId, monitorScoreHistoryTable.scanId))
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

  // ── GET /api/monitor/subscriptions/:id/pulses ────────────────────────────────
}

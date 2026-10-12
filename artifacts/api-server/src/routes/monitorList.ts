import { type IRouter } from "express";
import { TWENTY_FOUR_HOURS_MS, fetchLatestReport } from "./monitorShared";
import { db, monitorSubscriptionsTable, cveAlertsTable, reportsTable, monitorScoreHistoryTable, monitorRegressionsTable, certExpiryAlertsTable, monitorPulseChecksTable, scansTable } from "@workspace/db";
import { eq, and, gte, desc, count, inArray } from "drizzle-orm";
import { sameSite } from "../lib/urlKey";
import { monitorExpiryApplies } from "../lib/entitlements";
import { summariseUptime } from "../lib/monitorPulse";

/** GET and DELETE on /api/monitor/subscriptions. */



export function registerMonitorList(router: IRouter): void {

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

        // Whether a scan for this target is running right now.
        //
        // Without this the card had no way to know, so it showed the values from
        // before the scan and never changed: a subscription created seconds ago
        // read "Last scan: Never" while its baseline scan was already finishing,
        // and nothing refetched. A working product that looks broken is worse
        // than a broken one, because there is no reason to trust it afterwards.
        //
        // Matched on user + target rather than a subscription id because scans
        // deliberately carry no foreign key to a subscription (see scansTable) —
        // a scan is a historical record that outlives the subscription.
        const [inFlight] = await db
          .select({ id: scansTable.id, status: scansTable.status })
          .from(scansTable)
          .where(
            and(
              eq(scansTable.userId, sub.userId),
              sameSite(scansTable.targetUrl, sub.targetUrl),
              inArray(scansTable.status, ["queued", "scanning", "analyzing"]),
            ),
          )
          .orderBy(desc(scansTable.createdAt))
          .limit(1);

        // The hourly pulse. This is what the dashboard shows between scans: the
        // grade may be eleven days old, but "checked 12 minutes ago, answering in
        // 180ms, certificate good for 63 days" is current.
        const pulses24h = await db
          .select({
            reachable: monitorPulseChecksTable.reachable,
            responseTimeMs: monitorPulseChecksTable.responseTimeMs,
            checkedAt: monitorPulseChecksTable.checkedAt,
            httpStatus: monitorPulseChecksTable.httpStatus,
            certDaysRemaining: monitorPulseChecksTable.certDaysRemaining,
            failureReason: monitorPulseChecksTable.failureReason,
          })
          .from(monitorPulseChecksTable)
          .where(
            and(
              eq(monitorPulseChecksTable.subscriptionId, sub.id),
              gte(monitorPulseChecksTable.checkedAt, new Date(Date.now() - TWENTY_FOUR_HOURS_MS)),
            ),
          )
          .orderBy(desc(monitorPulseChecksTable.checkedAt));

        const uptime = summariseUptime(pulses24h);
        const newestPulse = pulses24h[0] ?? null;

        // Use the resolved scanAt so the card shows the correct date even before
        // the subscription row was backfilled.
        const lastScanAt = sub.lastScanAt ?? resolvedReport?.scannedAt ?? null;

        return {
          ...sub,
          lastScanAt,
          lastReport,
          alertCount,
          regressionCount: Number(regressionCount),
          // Prefer the live certificate reading over the one recorded when an
          // alert last fired: the alert row only exists inside 30 days, so
          // without this the dashboard could show nothing for a healthy cert.
          certExpiryDays: newestPulse?.certDaysRemaining ?? certExpiryDays,
          // False once plans are enforced: the plan decides then, so the card
          // must not count down to a date that no longer ends anything.
          expiryApplies: monitorExpiryApplies(),
          scanInProgress: Boolean(inFlight),
          scanStatus: inFlight?.status ?? null,
          lastPulseAt: newestPulse?.checkedAt ?? null,
          pulseReachable: newestPulse?.reachable ?? null,
          pulseStatus: newestPulse?.httpStatus ?? null,
          pulseFailureReason: newestPulse?.failureReason ?? null,
          responseTimeMs: newestPulse?.responseTimeMs ?? null,
          uptime24h: uptime.uptimePct,
          medianResponseMs: uptime.medianResponseMs,
          pulseChecks24h: uptime.checks,
          // Oldest-first, so the card can draw the last day left-to-right without
          // reversing it. Included here rather than fetched per card because the
          // rows are already in hand — one extra query per subscription on page
          // load, to draw a strip, would be a poor trade.
          pulseTimeline: [...pulses24h]
            .reverse()
            .map((p) => ({
              checkedAt: p.checkedAt,
              reachable: p.reachable,
              responseTimeMs: p.responseTimeMs,
            })),
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
}

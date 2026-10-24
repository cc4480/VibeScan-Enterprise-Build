import { resolveNextScanAt } from "./workerCadence";
import type { Log } from "./workerTypes";
import { db, reportsTable, monitorSubscriptionsTable, monitorScoreHistoryTable, monitorRegressionsTable } from "@workspace/db";
import { eq, and, desc } from "drizzle-orm";
import { computeNextScanAt } from "./monitorScheduler";
import { enforcementEnabled, rescanFloorDays } from "./entitlements";
import { hasLivePlan } from "./billing";
import { sendRegressionAlertEmail } from "./mailer";
import { findRegressions } from "./monitorRegressions";
import { highestSeverity } from "./notificationPrefs";
import { fireWebhook } from "./webhook";
import { type ScanVulnerability } from "./scanner";
import { findingFingerprint } from "./fingerprint";
import { newlyRunTests, type TestRecord } from "./testLedger";
import { APP_ORIGIN } from "./appOrigin";
import { autoFileRegressions } from "./githubIssuesAuto";
import { autoFileTickets } from "./ticketsAuto";

/** What the monitor bookkeeping needs to know about the scan that just completed. */
export interface MonitorScanInput {
  monitorSubscriptionId: string | null | undefined;
  userId: string;
  scanId: string;
  reportId: string;
  targetUrl: string;
  grade: string;
  riskScore: number;
  completedAt: Date;
  intercepted: boolean;
  severityCounts: Record<string, number>;
  tests: TestRecord[];
  vulnerabilities: ScanVulnerability[];
  log: Log;
}

/**
 * After a monitored scan: schedules the next one, writes the score snapshot, detects regressions
 * against the previous scan, and fires the webhooks. Never throws — a failure here must not fail
 * the scan that already produced a report.
 */
export async function recordMonitorScan(input: MonitorScanInput): Promise<void> {
  const { monitorSubscriptionId, userId, scanId, targetUrl, grade, riskScore, completedAt, intercepted, severityCounts, tests, log } = input;
  const report = { id: input.reportId };
  const scanResult = { vulnerabilities: input.vulnerabilities };
  if (monitorSubscriptionId) {
    try {
      // Fetch current subscription for webhook URL and email
      const [sub] = await db
        .select()
        .from(monitorSubscriptionsTable)
        .where(eq(monitorSubscriptionsTable.id, monitorSubscriptionId))
        .limit(1);

      // A free account's site is held to weekly rescans once plans are enforced.
      // Unenforced, nobody is on a "free plan", so nothing changes today. If the
      // plan lookup fails the floor is skipped: one extra rescan costs less than a
      // monitor that stops being scheduled.
      let floorDays = 0;
      if (enforcementEnabled()) {
        try {
          floorDays = rescanFloorDays({ enforced: true, hasLivePlan: await hasLivePlan(userId) });
        } catch (err) {
          log.warn({ err, monitorSubscriptionId }, "Could not read the plan; not applying the free-site rescan floor");
        }
      }
      const gradeCadenceAt = computeNextScanAt(grade, completedAt, { minDays: floorDays, intervalDays: sub?.scanIntervalDays });
      const nextScanAt = resolveNextScanAt(sub?.nextScanAt ?? null, gradeCadenceAt, completedAt);

      // .returning() so the log reflects what actually happened.
      //
      // Without it this logged "Monitor subscription updated" identically
      // whether the WHERE matched a row or nothing at all — so when a user
      // reported that monitoring "isn't saving the scan", the logs were
      // useless as evidence either way. The WHERE carries a userId as well as
      // an id, so a subscription cancelled or reassigned mid-scan matches
      // nothing, and that is worth a warning rather than a success line.
      const updatedSubs = await db
        .update(monitorSubscriptionsTable)
        .set({
          lastScanAt: completedAt,
          lastReportId: report.id,
          nextScanAt,
        })
        .where(
          and(
            eq(monitorSubscriptionsTable.id, monitorSubscriptionId),
            eq(monitorSubscriptionsTable.userId, userId),
          ),
        )
        .returning({ id: monitorSubscriptionsTable.id });

      if (updatedSubs.length === 0) {
        log.warn(
          { monitorSubscriptionId, reportId: report.id },
          "Monitor subscription NOT updated — no row matched this id and user",
        );
      } else {
        log.info(
          { monitorSubscriptionId, reportId: report.id, grade, nextScanAt },
          "Monitor subscription updated",
        );
      }

      // A challenge-answered scan is not a valid monitoring datapoint.
      // Recording its withheld findings as a score posts a false "improved"
      // reading to the trend and makes every withheld check look "fixed",
      // which then fires a regression storm on the next real scan. Skip the
      // snapshot and the regression comparison entirely. The re-scan cadence
      // already tightens on its own: nextScanDelayDays returns 3 days for any
      // non-A/B/C grade, and the N/A sentinel is one, so the next attempt is
      // brought forward rather than left on the 14-day A cadence.
      if (intercepted) {
        log.info(
          { monitorSubscriptionId },
          "Scan intercepted — skipping score snapshot and regression detection",
        );
      } else {
      // ── Score snapshot ──────────────────────────────────────────────
      const criticalCount = severityCounts["critical"] ?? 0;
      const highCount = severityCounts["high"] ?? 0;

      await db.insert(monitorScoreHistoryTable).values({
        subscriptionId: monitorSubscriptionId,
        scanId,
        grade,
        riskScore,
        criticalCount,
        highCount,
        scannedAt: completedAt,
      });

      log.info({ monitorSubscriptionId, grade, riskScore }, "Score history snapshot saved");

      // ── Regression detection ────────────────────────────────────────
      // Compare current vuln check IDs against the *previous* snapshot
      const [prevHistory] = await db
        .select()
        .from(monitorScoreHistoryTable)
        .where(eq(monitorScoreHistoryTable.subscriptionId, monitorSubscriptionId))
        .orderBy(desc(monitorScoreHistoryTable.scannedAt))
        .offset(1)
        .limit(1);

      if (prevHistory) {
        // Get previous scan's vulnerabilities from that scan's report
        const [prevReport] = await db
          .select({ data: reportsTable.data })
          .from(reportsTable)
          .where(eq(reportsTable.scanId, prevHistory.scanId!))
          .limit(1);

        if (prevReport) {
          type VulnShape = { category: string; name: string; evidence?: string | null; severity: string };
          const prevData = prevReport.data as { vulnerabilities?: VulnShape[] };
          const prevFingerprints = new Set(
            (prevData.vulnerabilities ?? []).map((v) =>
              findingFingerprint(v.category, v.name, v.evidence),
            ),
          );

          // A finding the previous scan could not have produced — because the
          // test behind it did not run then (most often: the domain was
          // verified in between, so the active tests ran for the first time)
          // — did not "start failing". When coverage grew, there is no honest
          // baseline for this scan's new findings, so none are called
          // regressions; they are in the report, and the next scan compares
          // like with like.
          const newlyRun = newlyRunTests((prevReport.data as { tests?: unknown }).tests, tests);
          if (newlyRun.length > 0) {
            log.info(
              { subscriptionId: monitorSubscriptionId, newlyRun },
              "More tests ran than on the previous scan — new findings are not treated as regressions",
            );
          }
          const newRegressions = newlyRun.length > 0 ? [] : findRegressions(scanResult.vulnerabilities, prevFingerprints);

          if (newRegressions.length > 0) {
            log.info(
              { subscriptionId: monitorSubscriptionId, regressions: newRegressions.length },
              "Regressions detected",
            );

            await db.insert(monitorRegressionsTable).values(
              newRegressions.map((v) => ({
                subscriptionId: monitorSubscriptionId,
                scanId,
                checkId: findingFingerprint(v.category, v.name, v.evidence),
                checkTitle: v.name,
                severity: v.severity,
              })),
            ).onConflictDoNothing();

            const appOrigin = APP_ORIGIN;

            if (sub?.userEmail) {
              await sendRegressionAlertEmail({
                toEmail: sub.userEmail,
                userId: sub.userId,
                targetUrl,
                regressions: newRegressions.map((v) => ({
                  checkTitle: v.name,
                  severity: v.severity,
                })),
                scanId,
                dashboardUrl: `${appOrigin}/monitor`,
              }).catch((err) =>
                log.warn({ err }, "Failed to send regression email (non-fatal)"),
              );
            }

            if (sub?.webhookUrl) {
              await fireWebhook(
                sub.webhookUrl,
                "regression_detected",
                targetUrl,
                monitorSubscriptionId,
                {
                  regressions: newRegressions.map((v) => ({
                    checkTitle: v.name,
                    severity: v.severity,
                  })),
                  scanId,
                  grade,
                  riskScore,
                },
                {
                  userId,
                  // Worst of the batch — see highestSeverity.
                  severity: highestSeverity(
                    newRegressions.map((v) => ({ severity: v.severity })),
                  ),
                },
              ).catch((err) =>
                log.warn({ err }, "Failed to fire regression webhook (non-fatal)"),
              );
            }

            // Only when the account has switched it on (Settings, GitHub issues). Never throws.
            await autoFileRegressions({ userId, reportId: report.id, regressions: newRegressions, log });
            await autoFileTickets({ userId, reportId: report.id, regressions: newRegressions, log });
          }
        }
      }
      } // end else (scan was not intercepted)

      // ── Fire scan_complete webhook ──────────────────────────────────
      if (sub?.webhookUrl) {
        const appOrigin = APP_ORIGIN;
        await fireWebhook(
          sub.webhookUrl,
          "scan_complete",
          targetUrl,
          monitorSubscriptionId,
          {
            scanId,
            reportId: report.id,
            grade,
            riskScore,
            reportUrl: `${appOrigin}/report/${report.id}`,
          },
          { userId },
        ).catch((err) => log.warn({ err }, "Failed to fire scan_complete webhook (non-fatal)"));
      }
    } catch (monitorErr) {
      log.warn({ err: monitorErr }, "Failed to update monitor subscription (non-fatal)");
    }
  }
}

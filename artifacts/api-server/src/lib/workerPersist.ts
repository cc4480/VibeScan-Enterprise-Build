/**
 * Saving the finished report and closing the scan: store the report, mark the scan complete, judge a
 * re-check, record a monitor's result and send the notification. If the report cannot be stored the scan is
 * failed and refunded. Split from workerJob.ts, which produces everything passed in here.
 */
import type { ScanResult } from "./scanner";
import { db, scansTable, reportsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { completeVerification, failVerificationForScan } from "./verifyFix";
import { refundFailedScan } from "./billing";
import { recordMonitorScan } from "./workerMonitor";
import { sendReportReadyNotification } from "./workerEmail";
import { recordSideTests } from "./workerSideChecks";
import { buildReport } from "./workerReport";

type Log = import("pino").Logger<never, boolean>;
type Built = Awaited<ReturnType<typeof buildReport>>;

export interface PersistInput {
  scanId: string;
  userId: string;
  targetUrl: string;
  tier: string;
  verificationId?: string | null | undefined;
  monitorSubscriptionId?: string | null | undefined;
  scanResult: ScanResult;
  tests: Awaited<ReturnType<typeof recordSideTests>>;
  reportData: Built["reportData"];
  riskScore: Built["riskScore"];
  grade: Built["grade"];
  intercepted: Built["intercepted"];
  severityCounts: Built["severityCounts"];
  executiveSummary: Built["executiveSummary"];
  log: Log;
}

export async function persistReport(input: PersistInput): Promise<void> {
  const {
    scanId, userId, targetUrl, tier, verificationId, monitorSubscriptionId, scanResult, tests,
    reportData, riskScore, grade, intercepted, severityCounts, executiveSummary, log,
  } = input;

  // ── 6. Persist report ─────────────────────────────────────────────────
  const completedAt = new Date();

  try {
    const [report] = await db
      .insert(reportsTable)
      .values({
        scanId,
        userId,
        targetUrl: scanResult.finalUrl || targetUrl,
        tier: tier as "basic" | "deep" | "pack_5" | "pack_20",
        duration: scanResult.requestDurationMs,
        data: reportData,
      })
      .returning();

    log.info({ reportId: report.id }, "Report saved to database");

    // ── 7. Mark scan complete ─────────────────────────────────────────
    await db
      .update(scansTable)
      // Credentials live exactly as long as the scan that needed them.
      .set({ status: "complete", completedAt, credentialsEncrypted: null, secondaryCredentialsEncrypted: null })
      .where(eq(scansTable.id, scanId));

    log.info({ reportId: report.id, grade, riskScore }, "Scan complete");

    // A re-check of one finding (lib/verifyFix.ts): judge it against the report that held it.
    if (verificationId) {
      const verdict = await completeVerification(verificationId, reportData).catch((err) => {
        log.error({ err }, "Could not record the verification verdict");
        return null;
      });
      log.info({ verificationId, verdict }, "Verification complete");
    }
    // The report is saved. A failure in what follows must not reach the catch below, which marks the
    // scan failed and refunds it while the report stays.
    await recordMonitorScan({
      monitorSubscriptionId, userId, scanId, reportId: report.id, targetUrl, grade, riskScore,
      completedAt, intercepted, severityCounts, tests, vulnerabilities: scanResult.vulnerabilities, log,
    }).catch((err) => log.error({ err }, "Could not record the monitor scan after saving the report"));

    await sendReportReadyNotification({
      scanId, userId, verificationId, tier, targetUrl, report, scanResult, grade, riskScore, tests, executiveSummary, severityCounts,
    }).catch((err) => log.error({ err }, "Could not send the report-ready notification"));
  } catch (dbErr) {
    log.error({ err: dbErr }, "Failed to save report to database");
    await db
      .update(scansTable)
      .set({
        status: "failed",
        error: "Failed to save report — please contact support",
        completedAt,
        credentialsEncrypted: null,
        secondaryCredentialsEncrypted: null,
      })
      .where(eq(scansTable.id, scanId));
    await failVerificationForScan(scanId).catch(() => {});
    await refundIfPaid(scanId, log);
  }}

/**
 * A scan that failed gives back what paid for it — a bought credit, or one of
 * the subscription's included scans. Customers were previously charged for
 * scans the system never delivered. Idempotent (see refundFailedScan), and
 * never throws: the scan has already failed for its own reason, and a refund
 * error must not bury that.
 */
export async function refundIfPaid(scanId: string, log: { info: (o: object, m: string) => void; error: (o: object, m: string) => void }): Promise<void> {
  try {
    const refunded = await refundFailedScan(scanId);
    if (refunded) log.info({ scanId, refunded }, "Refunded the payment for a failed scan");
  } catch (err) {
    log.error({ err, scanId }, "Could not refund a failed scan — needs manual credit");
  }
}

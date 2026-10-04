import type { ScanResult } from "./scanner";
import { db, scansTable, reportsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { changesForReport } from "./scanDiffLoader";
import { summariseChanges } from "./scanDiff";
import { countTests, type TestRecord } from "./testLedger";
import { sendReportReadyEmail } from "./mailer";
import { APP_ORIGIN } from "./appOrigin";
import { splitScanNotes } from "./scanNotes";

/** Emails the owner that their report is ready (not for ownership-verification scans). */
export async function sendReportReadyNotification(input: {
  scanId: string;
  userId: string;
  verificationId: string | null | undefined;
  tier: string;
  targetUrl: string;
  report: typeof reportsTable.$inferSelect;
  scanResult: ScanResult;
  grade: string;
  riskScore: number;
  tests: TestRecord[];
  executiveSummary: string;
  severityCounts: Record<string, number>;
}): Promise<void> {
  const { scanId, userId, verificationId, tier, targetUrl, report, scanResult, grade, riskScore, tests, executiveSummary, severityCounts } = input;
  {
    const [scan] = await db
      .select({ userEmail: scansTable.userEmail })
      .from(scansTable)
      .where(eq(scansTable.id, scanId));

    if (scan?.userEmail && !verificationId) {
      const appOrigin = APP_ORIGIN;

      // The link is /report/:id, which needs a session (no share token is minted for the email).
      // The owner's full report, the same page as in the app. Opening it
      // signed out goes through sign-in and comes straight back here
      // (sign-in honours ?returnTo), so a phone that is not signed in still
      // lands on the report rather than a dead end.
      const reportUrl = `${appOrigin}/report/${report.id}`;

      // What changed since the last scan of this site. Optional flavour for the email: a failure
      // here must never stop the report being delivered.
      const changes = await changesForReport(userId, { scanId, targetUrl: report.targetUrl, scannedAt: report.scannedAt, data: report.data }).catch(() => null);

      await sendReportReadyEmail({
        toEmail: scan.userEmail,
        ...(changes && summariseChanges(changes) ? { changesLine: summariseChanges(changes) } : {}),
        targetUrl: scanResult.finalUrl || targetUrl,
        grade,
        riskScore,
        // The "Findings" tile counts findings about the site, as the report does; the scan's notes are not among them.
        totalVulns: splitScanNotes(scanResult.vulnerabilities).findings.length,
        reportUrl,
        tier,
        coverage: countTests(tests),
        executiveSummary,
        pagesScanned: Array.isArray(scanResult.pagesScanned) ? scanResult.pagesScanned.length : undefined,
        severity: {
          critical: severityCounts["critical"] ?? 0,
          high: severityCounts["high"] ?? 0,
          medium: severityCounts["medium"] ?? 0,
          low: severityCounts["low"] ?? 0,
          info: severityCounts["info"] ?? 0,
        },
      });
    }
  }
}

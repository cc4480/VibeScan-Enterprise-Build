import type { ScanResult } from "./scanner";
import { db, scansTable, reportsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { changesForReport } from "./scanDiffLoader";
import { summariseChanges } from "./scanDiff";
import { countTests, type TestRecord } from "./testLedger";
import { sendReportReadyEmail } from "./mailer";
import { APP_ORIGIN } from "./appOrigin";

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

      // The emailed link must resolve WITHOUT a session. /report/:id requires
      // being signed in as the report's owner, which fails on the most common
      // way people open mail: on a phone, logged out (401) or signed into a
      // different account (404) — both of which render as a bare "Failed to
      // load report", so the person the report was sent to could not read it.
      // Observed live: one report answered 200 on the device that ran the scan
      // and 404 on the owner's own phone, signed into their other account.
      //
      // A share token resolves through GET /api/share/:token, which takes no
      // session. It is a bearer credential for that ONE report, which is
      // acceptable because it is delivered only to the owner's own mailbox —
      // see lib/reportShare.ts. If minting it fails the email still goes out
      // with the dashboard link rather than not at all: a link that needs a
      // login beats no notification.
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
        totalVulns: scanResult.vulnerabilities.length,
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

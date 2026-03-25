/**
 * pg-boss worker — processes scan jobs from the queue.
 * Registered at startup by index.ts.
 *
 * Job lifecycle per scan:
 *   queued → scanning → analyzing → complete
 *              ↓ (on error)
 *            failed
 */

import { db, scansTable, reportsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { getBoss, SCAN_QUEUE, type ScanJobData } from "./queue";
import { runScan, computeRiskScore, computeGrade, type ScanVulnerability } from "./scanner";
import { callDeepSeek } from "./deepseek";
import { checkSslLabs } from "./ssllabs";
import { sendReportReadyEmail } from "./mailer";
import { logger } from "./logger";
import { randomUUID } from "node:crypto";
import type { Job } from "pg-boss";

type ScanJob = Job<ScanJobData>;

async function processScanJob(job: ScanJob): Promise<void> {
  const { scanId, userId, targetUrl, tier } = job.data;
  const log = logger.child({ scanId, targetUrl, tier });

  log.info("Scan job started");

  // ── 1. Mark as scanning ───────────────────────────────────────────────
  await db
    .update(scansTable)
    .set({ status: "scanning", startedAt: new Date() })
    .where(eq(scansTable.id, scanId));

  // ── 2. Run header scan + SSL Labs check in parallel ───────────────────
  log.info("Running HTTP security scan and SSL Labs check in parallel");

  // SSL Labs is best-effort and can take up to 120 seconds — start it early
  const sslLabsPromise = checkSslLabs(targetUrl).catch((err) => {
    log.warn({ err }, "SSL Labs check failed (non-fatal)");
    return null;
  });

  let scanResult;
  try {
    scanResult = await runScan(targetUrl, tier);
    log.info(
      { vulnCount: scanResult.vulnerabilities.length, durationMs: scanResult.requestDurationMs },
      "HTTP scan complete",
    );
  } catch (scanErr) {
    const errMsg = scanErr instanceof Error ? scanErr.message : String(scanErr);
    log.error({ err: scanErr }, "Scan failed during HTTP fetch");
    await db
      .update(scansTable)
      .set({ status: "failed", error: errMsg, completedAt: new Date() })
      .where(eq(scansTable.id, scanId));
    return;
  }

  // Wait for SSL Labs (it was started in parallel with the header scan)
  log.info("Waiting for SSL Labs assessment to complete");
  const sslLabsResult = await sslLabsPromise;
  if (sslLabsResult) {
    log.info({ grade: sslLabsResult.grade, issues: sslLabsResult.issues.length }, "SSL Labs assessment complete");
    // Override the basic TLS grade with the real SSL Labs grade
    scanResult.tlsGrade = sslLabsResult.grade;

    // Add SSL Labs findings as vulnerabilities
    if (sslLabsResult.grade && /^[C-F]$/.test(sslLabsResult.grade)) {
      scanResult.vulnerabilities.push({
        id: randomUUID(),
        name: `Weak TLS Configuration (SSL Labs Grade: ${sslLabsResult.grade})`,
        severity: sslLabsResult.grade === "F" ? "critical" : sslLabsResult.grade === "D" ? "high" : "medium",
        category: "Transport Security",
        description: `SSL Labs graded your TLS configuration as ${sslLabsResult.grade}. This indicates weak cipher suites, outdated protocol support, or certificate issues that could expose users to downgrade attacks.`,
        evidence: sslLabsResult.issues.join("; ") || null,
        solution: "Use a modern TLS configuration: TLS 1.2 minimum, TLS 1.3 preferred, disable RC4/3DES/CBC-mode cipher suites, and enable HSTS. Use Mozilla's SSL Configuration Generator for server-specific settings.",
        cweId: "CWE-326",
        cvssScore: sslLabsResult.grade === "F" ? 9.1 : sslLabsResult.grade === "D" ? 7.5 : 5.3,
      } satisfies ScanVulnerability);
    }
  } else {
    log.warn("SSL Labs assessment not available — using basic TLS detection");
  }

  // ── 3. Mark as analyzing (AI phase) ──────────────────────────────────
  await db
    .update(scansTable)
    .set({ status: "analyzing" })
    .where(eq(scansTable.id, scanId));

  // ── 4. AI analysis (deep tier and above) ─────────────────────────────
  let aiAnalysis = null;
  if (tier === "deep" || tier === "pack_5" || tier === "pack_20") {
    log.info("Calling DeepSeek AI analysis");
    aiAnalysis = await callDeepSeek(
      targetUrl,
      scanResult.vulnerabilities,
      scanResult.technologies,
      tier,
    );
    if (aiAnalysis) {
      log.info("DeepSeek analysis complete");
    } else {
      log.warn("DeepSeek analysis skipped or failed — continuing without AI");
    }
  }

  // ── 5. Build report data ──────────────────────────────────────────────
  const riskScore = computeRiskScore(scanResult.vulnerabilities);
  const grade = computeGrade(riskScore);

  const severityCounts = scanResult.vulnerabilities.reduce(
    (acc, v) => {
      acc[v.severity] = (acc[v.severity] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const executiveSummary = buildExecutiveSummary(
    grade,
    riskScore,
    targetUrl,
    scanResult.vulnerabilities.length,
    severityCounts,
  );

  const reportData = {
    targetUrl: scanResult.finalUrl || targetUrl,
    vulnerabilities: scanResult.vulnerabilities,
    technologies: scanResult.technologies,
    server: scanResult.server,
    tlsGrade: scanResult.tlsGrade,
    summary: {
      totalVulnerabilities: scanResult.vulnerabilities.length,
      critical: severityCounts["critical"] ?? 0,
      high: severityCounts["high"] ?? 0,
      medium: severityCounts["medium"] ?? 0,
      low: severityCounts["low"] ?? 0,
      info: severityCounts["info"] ?? 0,
      riskScore,
      grade,
      executiveSummary,
    },
    aiAnalysis: aiAnalysis ?? undefined,
  };

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
      .set({ status: "complete", completedAt })
      .where(eq(scansTable.id, scanId));

    log.info({ reportId: report.id, grade, riskScore }, "Scan complete");

    // ── 8. Send report-ready email (deep / pack tiers only) ───────────
    const isDeep = tier === "deep" || tier === "pack_5" || tier === "pack_20";
    if (isDeep) {
      const [scan] = await db
        .select({ userEmail: scansTable.userEmail })
        .from(scansTable)
        .where(eq(scansTable.id, scanId));

      if (scan?.userEmail) {
        const appOrigin = process.env.APP_ORIGIN ?? "https://vibescan.app";
        await sendReportReadyEmail({
          toEmail: scan.userEmail,
          targetUrl: scanResult.finalUrl || targetUrl,
          grade,
          riskScore,
          totalVulns: scanResult.vulnerabilities.length,
          reportUrl: `${appOrigin}/report/${report.id}`,
          tier,
        });
      }
    }
  } catch (dbErr) {
    log.error({ err: dbErr }, "Failed to save report to database");
    await db
      .update(scansTable)
      .set({
        status: "failed",
        error: "Failed to save report — please contact support",
        completedAt,
      })
      .where(eq(scansTable.id, scanId));
  }
}

function buildExecutiveSummary(
  grade: string,
  riskScore: number,
  targetUrl: string,
  totalVulns: number,
  counts: Record<string, number>,
): string {
  const domain = (() => {
    try { return new URL(targetUrl).hostname; } catch { return targetUrl; }
  })();

  const critical = counts["critical"] ?? 0;
  const high = counts["high"] ?? 0;

  if (totalVulns === 0) {
    return `${domain} passed all security checks with a grade of ${grade}. No significant vulnerabilities were detected during this scan. Continue following security best practices and re-scan regularly.`;
  }

  const urgencyPhrase =
    critical > 0
      ? `${critical} critical issue${critical > 1 ? "s" : ""} requiring immediate attention`
      : high > 0
        ? `${high} high-severity issue${high > 1 ? "s" : ""} that should be addressed promptly`
        : `${totalVulns} security findings, none of which are immediately critical`;

  return `Security scan of ${domain} identified ${urgencyPhrase}, yielding an overall grade of ${grade} with a risk score of ${riskScore}/100. Review the findings below and prioritise the high and critical items first.`;
}

export async function startWorker(): Promise<void> {
  const boss = await getBoss();

  // pg-boss v12 requires queues to be explicitly created before workers can bind
  await boss.createQueue(SCAN_QUEUE, {
    retryLimit: 2,
    retryDelay: 30,
    expireInSeconds: 7200,
  });

  await boss.work<ScanJobData>(SCAN_QUEUE, { localConcurrency: 2 }, async (jobs) => {
    for (const job of jobs) {
      try {
        await processScanJob(job);
      } catch (err) {
        logger.error({ err, jobId: job.id }, "Unexpected error processing scan job");
        throw err;
      }
    }
  });

  logger.info({ queue: SCAN_QUEUE }, "Scan worker registered and listening");
}

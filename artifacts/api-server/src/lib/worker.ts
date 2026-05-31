/**
 * pg-boss worker — processes scan jobs from the queue.
 * Registered at startup by index.ts.
 *
 * Job lifecycle per scan:
 *   queued → scanning → analyzing → complete
 *              ↓ (on error)
 *            failed
 */

import {
  db, scansTable, reportsTable, monitorSubscriptionsTable, dismissedFindingsTable,
  monitorScoreHistoryTable, monitorRegressionsTable,
} from "@workspace/db";
import { eq, and, desc } from "drizzle-orm";
import { computeNextScanAt } from "./monitorScheduler";
import { sendRegressionAlertEmail } from "./mailer";
import { fireWebhook } from "./webhook";
import { getBoss, SCAN_QUEUE, type ScanJobData } from "./queue";
import { runScan, computeRiskScore, computeGrade, type ScanVulnerability } from "./scanner";
import { corroborateMerge } from "./scoring";
import { findingFingerprint, normalizeEvidenceKey, canonicalizeTargetUrl } from "./fingerprint";
import { runRecon } from "./recon";
import { warnIfLocalDataStale, OSV_CACHE_MAX_SIZE } from "./cveCheck";
import { refreshEolData, loadEolCacheFromDb, EOL_REFRESH_QUEUE } from "./eolFetcher";
import { callDeepSeek } from "./deepseek";
import { checkSslLabs } from "./ssllabs";
import { sendReportReadyEmail } from "./mailer";
import { logger } from "./logger";
import { randomUUID } from "node:crypto";
import * as tls from "node:tls";
import type { Job } from "pg-boss";

/** Probe the TLS certificate expiry date for an https:// URL. Returns null for HTTP or on error. */
async function getCertExpiry(url: string): Promise<Date | null> {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return null;
    const host = parsed.hostname;
    const port = parseInt(parsed.port || "443", 10);
    return await new Promise<Date | null>((resolve) => {
      const socket = tls.connect(
        { host, port, servername: host, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          if (!cert || !cert.valid_to) { resolve(null); return; }
          resolve(new Date(cert.valid_to));
        },
      );
      socket.on("error", () => resolve(null));
      socket.setTimeout(8_000, () => { socket.destroy(); resolve(null); });
    });
  } catch {
    return null;
  }
}

type ScanJob = Job<ScanJobData>;

// ─── Differential re-probe ────────────────────────────────────────────────────

const REPROBE_MIN = 50;
const REPROBE_MAX = 70;
const REPROBE_TIMEOUT_MS = 15_000;

/**
 * For borderline findings (50 ≤ confidence < 70), makes a second HTTP request
 * to the target URL and re-verifies header-based conditions.
 * Confirmed findings get +10 confidence; contradicted ones get -20.
 */
interface ReprobeLog {
  info: (obj: Record<string, unknown>, msg: string) => void;
  warn: (obj: unknown, msg: string) => void;
}

async function reprobe(
  targetUrl: string,
  vulns: ScanVulnerability[],
  log: ReprobeLog,
): Promise<ScanVulnerability[]> {
  const borderline = vulns.filter((v) => {
    const c = v.confidence ?? 100;
    return c >= REPROBE_MIN && c < REPROBE_MAX;
  });
  if (borderline.length === 0) return vulns;

  log.info({ borderlineCount: borderline.length }, "[reprobe] Re-probing borderline findings");

  // ── Single global 15s budget shared across all probes ───────────────────────
  const globalCtrl = new AbortController();
  const globalTimer = setTimeout(() => globalCtrl.abort(), REPROBE_TIMEOUT_MS);

  // Determine which probe types are needed
  const hasBorderlineCors = borderline.some(
    (v) => /cors/i.test(v.category) || /cors.*wildcard|access.control.allow.origin/i.test(v.name),
  );
  const hasBorderlineDns = borderline.some(
    (v) => /spf|dmarc|dkim|dnssec|email.*security|dns/i.test(v.name),
  );

  // Extract hostname for DNS probe
  let targetHostname = "";
  try { targetHostname = new URL(targetUrl).hostname; } catch { /* ignore */ }

  // ── Launch all probes in parallel under the shared 15s budget ────────────────

  // Probe 1: Passive GET — re-validates all header-based findings
  const getProbe = fetch(targetUrl, {
    method: "GET",
    signal: globalCtrl.signal,
    redirect: "follow",
    headers: { "Cache-Control": "no-cache, no-store", "Pragma": "no-cache" },
  }).then((res) => {
    const raw: Record<string, string> = {};
    res.headers.forEach((value, key) => { raw[key.toLowerCase()] = value; });
    return raw;
  }).catch(() => null as Record<string, string> | null);

  // Probe 2: Active OPTIONS — corroborates CORS wildcard findings
  const corsProbe = hasBorderlineCors
    ? fetch(targetUrl, {
        method: "OPTIONS",
        headers: {
          "Origin": "https://cors-probe.seclayer.io",
          "Access-Control-Request-Method": "GET",
        },
        signal: globalCtrl.signal,
        redirect: "follow",
      }).then((res) => {
        const raw: Record<string, string> = {};
        res.headers.forEach((value, key) => { raw[key.toLowerCase()] = value; });
        return raw;
      }).catch(() => null as Record<string, string> | null)
    : Promise.resolve(null as Record<string, string> | null);

  // Probe 3: DNS TXT probe — corroborates SPF/DMARC/email-security findings
  const dnsProbe = (hasBorderlineDns && targetHostname)
    ? fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(targetHostname)}&type=TXT`,
        { headers: { Accept: "application/dns-json" }, signal: globalCtrl.signal },
      ).then((res) => res.json() as Promise<{ Answer?: Array<{ data: string }> }>)
       .then((data) => data.Answer?.map((a) => a.data.toLowerCase()) ?? [] as string[])
       .catch(() => null as string[] | null)
    : Promise.resolve(null as string[] | null);

  let freshHeaders: Record<string, string> | null;
  let corsProbeHeaders: Record<string, string> | null;
  let dnsTxtRecords: string[] | null;

  try {
    [freshHeaders, corsProbeHeaders, dnsTxtRecords] = await Promise.all([getProbe, corsProbe, dnsProbe]);
  } finally {
    clearTimeout(globalTimer);
  }

  if (!freshHeaders) {
    log.warn({}, "[reprobe] GET re-probe failed — keeping original confidences");
    return vulns;
  }

  let boosted = 0;
  let dropped = 0;

  const updated = vulns.flatMap((v) => {
    const c = v.confidence ?? 100;
    if (c < REPROBE_MIN || c >= REPROBE_MAX) return [v];

    const vName = v.name.toLowerCase();
    const vCat = v.category.toLowerCase();

    // DNS-based findings: use TXT record probe result
    if (/spf|dmarc|dkim|dnssec|email.*security/i.test(vName) && dnsTxtRecords !== null) {
      const confirmed = checkDnsFinding(vName, dnsTxtRecords);
      if (confirmed !== null) {
        if (confirmed) { boosted++; return [{ ...v, confidence: Math.min(95, c + 10) }]; }
        dropped++;
        return [];
      }
    }

    // For CORS findings, prefer the active OPTIONS probe result
    const isCors = /cors/i.test(vCat) || /cors.*wildcard|access.control.allow.origin/i.test(vName);
    const headersToCheck = (isCors && corsProbeHeaders) ? corsProbeHeaders : freshHeaders;
    if (!headersToCheck) return [v];

    const confirmed = checkHeaderFinding(v, headersToCheck);
    if (confirmed === null) return [v]; // finding class not verifiable by any current probe — keep as-is
    if (confirmed) { boosted++; return [{ ...v, confidence: Math.min(95, c + 10) }]; }
    dropped++; // disconfirmed — remove from report
    return [];
  });

  log.info({ boosted, dropped }, "[reprobe] Re-probe adjustments applied");
  return updated;
}

/**
 * Validates DNS-based security findings against live TXT record data from
 * a DNS-over-HTTPS probe. Returns true if the finding is confirmed (issue
 * still present), false if disconfirmed, or null if undecidable.
 */
function checkDnsFinding(nameLower: string, txtRecords: string[]): boolean | null {
  if (/spf|sender policy framework/.test(nameLower))
    return !txtRecords.some((r) => r.includes("v=spf1"));
  if (/dmarc/.test(nameLower))
    return !txtRecords.some((r) => r.includes("v=dmarc1"));
  if (/dkim/.test(nameLower))
    return !txtRecords.some((r) => r.includes("v=dkim1"));
  return null;
}

function checkHeaderFinding(
  vuln: ScanVulnerability,
  headers: Record<string, string>,
): boolean | null {
  const name = vuln.name.toLowerCase();
  const cat = vuln.category.toLowerCase();

  if (/hsts|strict-transport/.test(name))
    return !("strict-transport-security" in headers);
  if (/content.security.policy|(?<!\w)csp(?!\w)/.test(name) && /missing|absent/.test(name))
    return !("content-security-policy" in headers);
  if (/x-frame|clickjack/.test(name)) {
    if (/missing|absent/.test(name)) return !("x-frame-options" in headers);
    const val = headers["x-frame-options"] ?? "";
    return !val || !/^(deny|sameorigin)$/i.test(val.trim());
  }
  if (/x-content-type|content.type.sniff/.test(name)) {
    const val = (headers["x-content-type-options"] ?? "").toLowerCase().trim();
    return val !== "nosniff";
  }
  if (/referrer-policy/.test(name) && /missing|absent/.test(name))
    return !("referrer-policy" in headers);
  if (/permissions.policy|feature.policy/.test(name) && /missing|absent/.test(name))
    return !("permissions-policy" in headers) && !("feature-policy" in headers);
  if (cat.includes("cors") || /\bcors\b/.test(name))
    return headers["access-control-allow-origin"] === "*";
  if (/server version|server disclosure/.test(name)) {
    const srv = headers["server"] ?? "";
    return /[0-9]+\.[0-9]+/.test(srv);
  }
  if (/x-powered-by/.test(name))
    return "x-powered-by" in headers;
  // Cookie flag checks — best effort from Set-Cookie in the fresh response
  if (/cookie.*secure|secure.*cookie/.test(name)) {
    const sc = headers["set-cookie"] ?? "";
    return sc.length > 0 && !/;\s*secure/i.test(sc);
  }
  if (/cookie.*httponly|httponly/.test(name)) {
    const sc = headers["set-cookie"] ?? "";
    return sc.length > 0 && !/;\s*httponly/i.test(sc);
  }
  if (/cookie.*samesite|samesite/.test(name)) {
    const sc = headers["set-cookie"] ?? "";
    return sc.length > 0 && !/;\s*samesite/i.test(sc);
  }

  return null;
}

async function processScanJob(job: ScanJob): Promise<void> {
  const { scanId, userId, targetUrl, tier, monitorSubscriptionId } = job.data;
  const log = logger.child({ scanId, targetUrl, tier, monitorSubscriptionId });

  log.info("Scan job started");

  // ── 1. Mark as scanning ───────────────────────────────────────────────
  await db
    .update(scansTable)
    .set({ status: "scanning", startedAt: new Date() })
    .where(eq(scansTable.id, scanId));

  // ── 2. Run header scan + SSL Labs check in parallel ───────────────────
  log.info("Starting HTTP scan, SSL Labs check, and reconnaissance in parallel");

  // SSL Labs is best-effort and can take up to 120 seconds — start it early
  const sslLabsPromise = checkSslLabs(targetUrl).catch((err) => {
    log.warn({ err }, "SSL Labs check failed (non-fatal)");
    return null;
  });

  // Recon runs concurrently: DNS enumeration, subdomain brute-force, port scan
  const reconPromise = runRecon(targetUrl).catch((err) => {
    log.warn({ err }, "Recon failed (non-fatal)");
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

  // ── 2b. Merge reconnaissance results ─────────────────────────────────
  log.info("Waiting for reconnaissance to complete");
  const reconRunResult = await reconPromise;
  if (reconRunResult) {
    // Dangerous-port findings surface as first-class vulnerabilities
    scanResult.vulnerabilities.push(...reconRunResult.vulns);
    log.info(
      {
        portVulns: reconRunResult.vulns.length,
        openPorts: reconRunResult.recon.openPorts.length,
        subdomains: reconRunResult.recon.subdomains.length,
        dnsRecords: reconRunResult.recon.dnsRecords.length,
      },
      "Recon complete — merged into scan result",
    );
  } else {
    log.warn("Recon results unavailable — continuing without reconnaissance data");
  }

  // ── 2c. Corroboration merge — deduplicate duplicate-root-cause findings ──
  const preCorrobCount = scanResult.vulnerabilities.length;
  scanResult.vulnerabilities = corroborateMerge(scanResult.vulnerabilities);
  log.info(
    { before: preCorrobCount, after: scanResult.vulnerabilities.length },
    "Corroboration merge complete",
  );

  // ── 2d. Differential re-probe — re-verify borderline findings ────────
  scanResult.vulnerabilities = await reprobe(targetUrl, scanResult.vulnerabilities, log);

  // ── 2e. Filter previously dismissed false positives ───────────────────
  // Use the same canonicalized URL as the dismissals route so DB keys always match.
  // canonicalizeTargetUrl: lowercase scheme+host, strip trailing slash on non-root paths.
  const canonicalUrl = canonicalizeTargetUrl(scanResult.finalUrl ?? targetUrl);
  const dismissals = await db
    .select({ fingerprint: dismissedFindingsTable.findingFingerprint })
    .from(dismissedFindingsTable)
    .where(
      and(
        eq(dismissedFindingsTable.userId, userId),
        eq(dismissedFindingsTable.targetUrl, canonicalUrl),
      ),
    );

  let autoSuppressedCount = 0;
  if (dismissals.length > 0) {
    const dismissedFps = new Set(dismissals.map((d) => d.fingerprint));
    const beforeDismiss = scanResult.vulnerabilities.length;
    scanResult.vulnerabilities = scanResult.vulnerabilities.filter(
      (v) => !dismissedFps.has(findingFingerprint(v.category, v.name, normalizeEvidenceKey(v.evidence))),
    );
    autoSuppressedCount = beforeDismiss - scanResult.vulnerabilities.length;
    if (autoSuppressedCount > 0) {
      log.info({ autoSuppressedCount }, "Auto-suppressed previously dismissed findings");
    }
  }

  // ── 3. Mark as analyzing (AI phase) ──────────────────────────────────
  await db
    .update(scansTable)
    .set({ status: "analyzing" })
    .where(eq(scansTable.id, scanId));

  // ── 4. AI analysis (deep tier only) ──────────────────────────────────
  // Note: pack_5/pack_20 are credit-purchase tiers — scan records are always
  // created with "basic" or "deep", so only "deep" needs to be checked here.
  let aiAnalysis = null;
  if (tier === "deep") {
    log.info("Calling DeepSeek AI analysis");
    // Confidence gate: only pass high-confidence findings to the AI to reduce noise
    const AI_CONFIDENCE_GATE = 65;
    const vulnsForAi = scanResult.vulnerabilities.filter(
      (v) => (v.confidence ?? 100) >= AI_CONFIDENCE_GATE,
    );
    log.info(
      { total: scanResult.vulnerabilities.length, gated: vulnsForAi.length },
      "Confidence-gated findings passed to AI",
    );
    aiAnalysis = await callDeepSeek(
      targetUrl,
      vulnsForAi,
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

  // Probe TLS cert expiry for https:// targets (non-blocking, failures are soft)
  const certExpiry = await getCertExpiry(scanResult.finalUrl || targetUrl).catch(() => null);

  const reportData = {
    targetUrl: scanResult.finalUrl || targetUrl,
    vulnerabilities: scanResult.vulnerabilities,
    technologies: scanResult.technologies,
    server: scanResult.server,
    tlsGrade: scanResult.tlsGrade,
    certExpiry: certExpiry ? certExpiry.toISOString() : null,
    pagesScanned: scanResult.pagesScanned,
    probedNotFound: scanResult.probedNotFound,
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
    recon: reconRunResult?.recon ?? undefined,
    aiAnalysis: aiAnalysis ?? undefined,
    autoSuppressedCount: autoSuppressedCount > 0 ? autoSuppressedCount : undefined,
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

    // ── 8. Update monitor subscription + write score history + detect regressions ──
    if (monitorSubscriptionId) {
      try {
        const nextScanAt = computeNextScanAt(grade, completedAt);

        // Fetch current subscription for webhook URL and email
        const [sub] = await db
          .select()
          .from(monitorSubscriptionsTable)
          .where(eq(monitorSubscriptionsTable.id, monitorSubscriptionId))
          .limit(1);

        await db
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
          );

        log.info(
          { monitorSubscriptionId, reportId: report.id, grade, nextScanAt },
          "Monitor subscription updated",
        );

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

            const newRegressions = scanResult.vulnerabilities.filter(
              (v) => !prevFingerprints.has(findingFingerprint(v.category, v.name, v.evidence)),
            );

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

              const appOrigin = process.env.APP_ORIGIN ?? "https://seclayer.io";

              if (sub?.userEmail) {
                await sendRegressionAlertEmail({
                  toEmail: sub.userEmail,
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
                ).catch((err) =>
                  log.warn({ err }, "Failed to fire regression webhook (non-fatal)"),
                );
              }
            }
          }
        }

        // ── Fire scan_complete webhook ──────────────────────────────────
        if (sub?.webhookUrl) {
          const appOrigin = process.env.APP_ORIGIN ?? "https://seclayer.io";
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
          ).catch((err) => log.warn({ err }, "Failed to fire scan_complete webhook (non-fatal)"));
        }
      } catch (monitorErr) {
        log.warn({ err: monitorErr }, "Failed to update monitor subscription (non-fatal)");
      }
    }

    // ── 9. Send report-ready email ────────────────────────────────────
    // Deep scans and monitor-triggered scans always send email.
    if (tier === "deep") {
      const [scan] = await db
        .select({ userEmail: scansTable.userEmail })
        .from(scansTable)
        .where(eq(scansTable.id, scanId));

      if (scan?.userEmail) {
        const appOrigin = process.env.APP_ORIGIN ?? "https://seclayer.io";
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
  // Log the effective OSV cache size so operators can confirm env var took effect
  logger.info(
    { osvCacheMaxSize: OSV_CACHE_MAX_SIZE, envVar: "OSV_CACHE_MAX_SIZE" },
    "[cveCheck] OSV cache initialised",
  );

  // Hydrate EOL cache from the last DB-persisted fetch BEFORE the staleness check
  // so that warnIfLocalDataStale() uses the live fetchedAt timestamp, not the
  // bundled LOCAL_VULN_DATA_UPDATED date, when persisted data is available.
  await loadEolCacheFromDb();

  // Check freshness — uses live DB timestamp when available, bundled date otherwise
  warnIfLocalDataStale();

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

  // ── EOL data auto-refresh ─────────────────────────────────────────────────
  // Scheduled daily at 03:00 UTC to keep PHP / Nginx / Apache EOL tables
  // current without manual code changes (fetches from endoflife.date API).
  await boss.createQueue(EOL_REFRESH_QUEUE);
  await boss.schedule(EOL_REFRESH_QUEUE, "0 3 * * *", {});
  await boss.work(EOL_REFRESH_QUEUE, async () => {
    await refreshEolData();
  });
  logger.info(
    { queue: EOL_REFRESH_QUEUE, cron: "0 3 * * *" },
    "EOL refresh schedule registered (daily 03:00 UTC)",
  );

  // Kick off a fresh fetch in the background to update the in-memory cache and DB.
  // Failures are logged at WARN; the DB-loaded or bundled fallback data stays active.
  void refreshEolData();
}

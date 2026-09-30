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
  monitorScoreHistoryTable, monitorRegressionsTable, usersTable,
} from "@workspace/db";
import { eq, and, desc, ne } from "drizzle-orm";
import { computeNextScanAt } from "./monitorScheduler";
import { sendRegressionAlertEmail } from "./mailer";
import { highestSeverity } from "./notificationPrefs";
import { fireWebhook } from "./webhook";
import { getBoss, SCAN_QUEUE, type ScanJobData } from "./queue";
import { runScan, computeRiskScore, gradeForResult, type ScanVulnerability } from "./scanner";
import { purgeExpiredOobTokens } from "./oobServer";
import { decryptCredentials, toScanHttpCredentials, looksSignedOut } from "./scanCredentials";
import { runWithScanHttp } from "./http";
import { corroborateMerge } from "./scoring";
import { findingFingerprint, canonicalizeTargetUrl } from "./fingerprint";
import { runRecon } from "./recon";
import { activeProbesUnlocked } from "./activeProbeGate";
import { createLiveProgress } from "./liveProgress";
import { completeVerification, failVerificationForScan } from "./verifyFix";
import { changesForReport } from "./scanDiffLoader";
import { summariseChanges } from "./scanDiff";
import { countTests, formatTestLine, formatTestSummary, newlyRunTests, NOT_VERIFIED, type TestRecord } from "./testLedger";
import { warnIfLocalDataStale, OSV_CACHE_MAX_SIZE } from "./cveCheck";
import { refreshEolData, loadEolCacheFromDb, EOL_REFRESH_QUEUE } from "./eolFetcher";
import { callDeepSeek } from "./deepseek";
import { checkSslLabs } from "./ssllabs";
import { sendReportReadyEmail } from "./mailer";
import { summariseCompliance, COMPLIANCE_DISCLAIMER } from "./compliance";
import { initBrowser, closeBrowser } from "./browser";
import { logger } from "./logger";
import { isAiAnalysisOptedOut, AI_OPT_OUT_NOTE } from "./aiOptOut";
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

/**
 * How soon a pending nextScanAt has to be to count as a deliberate follow-up
 * rather than an anti-double-pick sentinel.
 *
 * The CVE job sets nextScanAt = now + 24h before its scan runs, and that must
 * survive. Both the sweep and subscription creation ALSO write a placeholder —
 * now + 3 days — whose only job is to stop the next sweep tick picking a
 * subscription whose scan is still in flight. Those two intents were
 * indistinguishable, and the placeholder always won.
 */
const FOLLOW_UP_WINDOW_MS = 48 * 60 * 60 * 1000;

/**
 * Decide the next scan time after a completed scan.
 *
 * Exported for tests. The bug this replaces made the entire published cadence
 * a fiction: the sweep wrote a 3-day placeholder, the worker saw 3 days was
 * sooner than an A grade's 14 and "preserved" it, so every A and B/C site was
 * rescanned every 3 days instead of 14 or 7 — roughly five times the intended
 * scanning, and a claim on the marketing page that was never true. It shipped
 * in the same commit as the cadence it broke (e0a9372, 2026-05-31) and the
 * cadence tests never caught it, because they test the interval function in
 * isolation and nothing tested the two halves together.
 */
export function resolveNextScanAt(
  pending: Date | null,
  gradeCadenceAt: Date,
  completedAt: Date,
): Date {
  if (!pending) return gradeCadenceAt;
  if (pending <= completedAt) return gradeCadenceAt;

  // Only a genuinely imminent follow-up wins. A placeholder days out does not,
  // however much sooner than the grade cadence it happens to be.
  const isFollowUp = pending.getTime() - completedAt.getTime() <= FOLLOW_UP_WINDOW_MS;
  return isFollowUp && pending < gradeCadenceAt ? pending : gradeCadenceAt;
}

const OOB_PURGE_QUEUE = "oob-purge";
const STUCK_SCAN_QUEUE = "stuck-scan-cleanup";

type ScanJob = Job<ScanJobData>;

// ─── Differential re-probe ────────────────────────────────────────────────────

import { reprobe } from "./reprobe";
import { APP_ORIGIN } from "./appOrigin";
import { refundFailedScan, reapStuckScans } from "./billing";

/**
 * For borderline findings (50 ≤ confidence < 70), makes a second HTTP request
 * to the target URL and re-verifies header-based conditions.
 * Confirmed findings get +10 confidence; contradicted ones get -20.
 */

/**
 * Exported for tests. The guards below decide whether a scan runs at all and
 * whether a billed AI call is made, and reaching them through `startWorker`
 * would mean standing up pg-boss to assert on a branch that is pure logic.
 */
export async function processScanJob(job: ScanJob): Promise<void> {
  const { scanId, userId, targetUrl, tier, monitorSubscriptionId, verificationId } = job.data;
  const log = logger.child({ scanId, targetUrl, tier, monitorSubscriptionId, verificationId });

  log.info("Scan job started");

  // ── 1. Mark as scanning ───────────────────────────────────────────────
  //
  // The returned rows are an existence check that costs nothing: deleting an
  // account removes its scans (routes/account.ts) before the user row, so a
  // scan id that no longer resolves means the owner deleted the account while
  // this job sat in the queue. Without this the job ran the full scan and then
  // paid for an AI call, only to fail at the report insert on reports.scan_id's
  // foreign key — work and money spent on a report that cannot be stored and
  // nobody can ever read. Found by a concurrency test that deleted its accounts
  // seconds after queueing: 18 of 20 jobs reached DeepSeek before dying here.
  //
  // Safe as a guard because the scan row is committed before the job is
  // enqueued (routes/scans.ts), so a missing row is always a deletion and never
  // a job that overtook its own insert.
  // Also refuses a scan already marked failed: the stuck-scan cleanup
  // (billing.ts reapStuckScans) fails and REFUNDS scans that never finished,
  // and a late retry must not then run one for free.
  const scanning = await db
    .update(scansTable)
    .set({ status: "scanning", startedAt: new Date() })
    .where(and(eq(scansTable.id, scanId), ne(scansTable.status, "failed")))
    .returning({ id: scansTable.id });

  if (scanning.length === 0) {
    log.info("Scan row is gone (account deleted) or already failed and refunded; abandoning job before any work");
    return;
  }

  // ── 2. Run header scan + SSL Labs check in parallel ───────────────────
  log.info("Starting HTTP scan, SSL Labs check, and reconnaissance in parallel");

  // SSL Labs is best-effort and can take up to 120 seconds — start it early
  const parallelStartedAt = Date.now();
  const sslLabsPromise = checkSslLabs(targetUrl).catch((err) => {
    log.warn({ err }, "SSL Labs check failed (non-fatal)");
    return null;
  });

  // One decision, consulted by both the HTTP scan and recon, so a target can
  // never be port-scanned by a path that skipped the check the probes made.
  const allowActiveProbes = await activeProbesUnlocked(userId, targetUrl);
  if (!allowActiveProbes) {
    log.info("Domain not verified for this user — running passive checks only");
  }

  // Recon runs concurrently: DNS enumeration, subdomain brute-force, port scan
  const reconPromise = runRecon(targetUrl, allowActiveProbes).catch((err) => {
    log.warn({ err }, "Recon failed (non-fatal)");
    return null;
  });

  // Hard deadline for the entire HTTP scan phase.
  // Individual probes have per-request timeouts (5–10 s each) but the aggregate
  // across all deep-scan probes can still hang indefinitely on complex targets.
  // 3 minutes is generous for any legitimate target; it prevents zombie jobs.
  const SCAN_HTTP_TIMEOUT_MS = 3 * 60 * 1_000;

  let scanResult;
  // Declared out here so the re-probe below runs under the same credentials —
  // see the note at its call site.
  let httpCredentials: Awaited<ReturnType<typeof toScanHttpCredentials>> = null;
  let reauthenticate: (() => Promise<Awaited<ReturnType<typeof toScanHttpCredentials>>>) | null = null;
  let secondaryCredentials: Awaited<ReturnType<typeof toScanHttpCredentials>> = null;
  // Finished tests, saved as they happen so the progress page shows real ones.
  const live = createLiveProgress(scanId);
  try {
    const scanTimeout = new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`HTTP scan timed out after ${SCAN_HTTP_TIMEOUT_MS / 1000}s`)),
        SCAN_HTTP_TIMEOUT_MS,
      ),
    );
    // ── Credentials for an authenticated scan ────────────────────────────────
    // Loaded from the scan row rather than the job payload, decrypted here and
    // held only for this scan. A form login runs a real browser sign-in; if it
    // fails the scan continues unauthenticated rather than aborting, and says
    // so in the log.
    const [scanRow] = await db
      .select({
        blob: scansTable.credentialsEncrypted,
        secondBlob: scansTable.secondaryCredentialsEncrypted,
        githubRepoUrl: scansTable.githubRepoUrl,
        autoSecondAccount: scansTable.autoSecondAccount,
      })
      .from(scansTable)
      .where(eq(scansTable.id, scanId));

    if (scanRow?.blob) {
      const stored = decryptCredentials(scanRow.blob);
      if (!stored) {
        log.warn("Stored credentials could not be decrypted — scanning unauthenticated");
      } else {
        httpCredentials = await toScanHttpCredentials(stored, log);
        log.info(
          { mode: stored.mode, authenticated: httpCredentials !== null },
          "Credentialed scan requested",
        );
        // Only a form login can be replayed. A pasted cookie or bearer token
        // has no renewal path, so its expiry is recorded but not recovered.
        // The second account only matters when the first one worked — access
        // control is a comparison, and there is nothing to compare against a
        // session that never authenticated.
        if (httpCredentials && scanRow.secondBlob) {
          const secondStored = decryptCredentials(scanRow.secondBlob);
          if (secondStored) {
            secondaryCredentials = await toScanHttpCredentials(secondStored, log);
            log.info(
              { enabled: secondaryCredentials !== null },
              "Access-control testing: second account session",
            );
          }
        }

        if (stored.mode === "form") {
          reauthenticate = async () => {
            log.warn("Session appears to have expired — signing in again");
            return toScanHttpCredentials(stored, log);
          };
        }
      }
    }

    scanResult = await Promise.race([
      runScan(
        targetUrl,
        tier,
        allowActiveProbes,
        httpCredentials
          ? {
              credentials: httpCredentials,
              ...(secondaryCredentials ? { secondary: secondaryCredentials } : {}),
              detectSignedOut: looksSignedOut,
              ...(reauthenticate ? { onSessionLost: reauthenticate } : {}),
            }
          : undefined,
        // Threads the scan id through to the SSRF probe so its out-of-band
        // callbacks correlate back to this scan.
        scanId,
        live.add,
        // Per-scan opt-ins the requester made: a public repository to read for committed secrets, and
        // permission to create a second account through the target's signup form. Absent for scans that
        // asked for neither, including every monitor rescan.
        {
          ...(scanRow?.githubRepoUrl ? { githubRepoUrl: scanRow.githubRepoUrl } : {}),
          ...(scanRow?.autoSecondAccount ? { autoSecondAccount: true } : {}),
          // If the target redirects elsewhere, active probing continues only on a host this user verified.
          verifyHost: (url: string) => activeProbesUnlocked(userId, url),
        },
      ),
      scanTimeout,
    ]);
    // pageLoadMs is the first fetch of the target only; scanMs is the whole
    // HTTP scan (crawl, probes, active tests). Logging the former as
    // "durationMs" made a full scan look like it took 1.6 seconds.
    log.info(
      {
        vulnCount: scanResult.vulnerabilities.length,
        pageLoadMs: scanResult.requestDurationMs,
        scanMs: Date.now() - parallelStartedAt,
      },
      "HTTP scan complete",
    );
  } catch (scanErr) {
    await live.finish();
    const errMsg = scanErr instanceof Error ? scanErr.message : String(scanErr);
    log.error({ err: scanErr }, "Scan failed during HTTP fetch");
    await db
      .update(scansTable)
      // Discard credentials on the failure path too — a scan that died holding
      // a customer's password is exactly the row that should not keep it.
      .set({ status: "failed", error: errMsg, completedAt: new Date(), credentialsEncrypted: null, secondaryCredentialsEncrypted: null })
      .where(eq(scansTable.id, scanId));
    await failVerificationForScan(scanId).catch(() => {});
    await refundIfPaid(scanId, log);
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

  // ── 2b′. One log line per test ───────────────────────────────────────
  // Everything the scan was meant to run — the scanner's own ledger plus
  // SSL Labs and reconnaissance, which run beside it here — each with its
  // outcome, so "did every test fire?" is answered by the log, not inferred.
  const tests: TestRecord[] = [...(scanResult.tests ?? [])];
  const sideMs = Date.now() - parallelStartedAt;
  tests.push(
    sslLabsResult
      ? { group: "transport", name: `SSL Labs TLS grade (${sslLabsResult.grade ?? "no grade"})`, status: "ran", findings: sslLabsResult.grade && /^[C-F]$/.test(sslLabsResult.grade) ? 1 : 0, durationMs: sideMs }
      : { group: "transport", name: "SSL Labs TLS grade", status: "failed", findings: 0, durationMs: sideMs, reason: "assessment unavailable (basic TLS detection used)" },
  );
  if (reconRunResult) {
    const r = reconRunResult.recon;
    tests.push(
      { group: "recon", name: `DNS records (${r.dnsRecords.length})`, status: "ran", findings: 0, durationMs: r.reconDurationMs },
      { group: "recon", name: `subdomain enumeration (${r.subdomains.length} found)`, status: "ran", findings: 0, durationMs: r.reconDurationMs },
      allowActiveProbes
        ? { group: "recon", name: `port scan (${r.openPorts.length} open)`, status: "ran", findings: reconRunResult.vulns.length, durationMs: r.reconDurationMs }
        : { group: "recon", name: "port scan", status: "skipped", findings: 0, durationMs: 0, reason: NOT_VERIFIED },
    );
  } else {
    tests.push({ group: "recon", name: "reconnaissance (DNS, subdomains, ports)", status: "failed", findings: 0, durationMs: sideMs, reason: "recon did not return results" });
  }
  // The scanner's own tests were sent live as they ended; these were added here.
  for (const t of tests.slice(scanResult.tests?.length ?? 0)) live.add(t);
  await live.finish();
  for (const t of tests) {
    const line = formatTestLine(t);
    if (t.status === "failed") log.warn({ test: t }, line);
    else log.info({ test: t }, line);
  }
  log.info({ tests: tests.length }, formatTestSummary(tests));

  // ── 2c. Corroboration merge — deduplicate duplicate-root-cause findings ──
  const preCorrobCount = scanResult.vulnerabilities.length;
  scanResult.vulnerabilities = corroborateMerge(scanResult.vulnerabilities);
  log.info(
    { before: preCorrobCount, after: scanResult.vulnerabilities.length },
    "Corroboration merge complete",
  );

  // ── 2d. Differential re-probe — re-verify borderline findings ────────
  // Runs inside the same credential context as the scan. Re-probing a
  // credentialed scan anonymously would re-check every finding against the
  // signed-out page and then *delete* the ones it could not see — silently
  // discarding real findings from the authenticated surface.
  scanResult.vulnerabilities = await runWithScanHttp(
    { targetUrl, ...(httpCredentials ? { credentials: httpCredentials } : {}) },
    () => reprobe(targetUrl, scanResult.vulnerabilities, log),
  );

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
      // Raw evidence, not normalizeEvidenceKey(evidence): findingFingerprint
      // normalizes internally, and normalizeEvidenceKey is not idempotent — it
      // lowercases first, then substitutes a literal uppercase "N" for dotted
      // numerics, so a second pass turns "apache/N" into "apache/n" and the
      // hash stops matching what routes/dismissals.ts stored. Every dismissal
      // whose evidence named a version, IP or port silently came back.
      (v) => !dismissedFps.has(findingFingerprint(v.category, v.name, v.evidence)),
    );
    autoSuppressedCount = beforeDismiss - scanResult.vulnerabilities.length;
    if (autoSuppressedCount > 0) {
      log.info({ autoSuppressedCount }, "Auto-suppressed previously dismissed findings");
    }
  }

  // ── 3. Mark as analyzing (AI phase) ──────────────────────────────────
  //
  // Checked again for the same reason as step 1, because this is the last
  // moment before the only step that costs real money. A scan running when its
  // owner deletes the account gets this far with the deletion already done, and
  // the AI call would be billed for a report the insert below cannot store.
  // The window between here and that insert is still open — an account deleted
  // during the AI call itself lands in the catch at step 6, which fails the
  // scan cleanly rather than crashing — but that window is seconds wide instead
  // of the whole scan.
  const analyzing = await db
    .update(scansTable)
    .set({ status: "analyzing" })
    .where(eq(scansTable.id, scanId))
    .returning({ id: scansTable.id });

  if (analyzing.length === 0) {
    log.info("Scan row no longer exists — owner deleted their account; abandoning job before the AI call");
    return;
  }

  // ── 4. AI analysis ───────────────────────────────────────────────────
  let aiAnalysis = null;
  {
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

    // The owner may have chosen not to have findings sent to the language-model provider.
    const aiOptedOut = verificationId ? false : await isAiAnalysisOptedOut(userId).catch(() => false);
    if (aiOptedOut) log.info("AI analysis skipped: turned off by the account owner");

    aiAnalysis = verificationId || aiOptedOut ? null : await callDeepSeek(
      targetUrl,
      vulnsForAi,
      scanResult.technologies,
      tier,
      // What ran and what was skipped, so the analysis never calls an
      // untested area safe.
      tests,
    );
    if (aiOptedOut) {
      scanResult.vulnerabilities.push({
        id: randomUUID(),
        ...AI_OPT_OUT_NOTE,
        severity: "info",
        category: "Scan Coverage",
        cweId: null,
        cvssScore: null,
        wstgId: null,
        confidence: 100,
      } satisfies ScanVulnerability);
    } else if (aiAnalysis) {
      log.info("DeepSeek analysis complete");
    } else {
      log.warn("DeepSeek analysis skipped or failed — continuing without AI");

      // Tell the reader, not just the log. The written analysis is the part of
      // a report a developer without a security team actually acts on, and
      // when it is missing the report does not look degraded — it looks like a
      // report with less to say. Under load that is exactly when this happens:
      // the AI call has a 30s timeout and no retry, so one rate-limited
      // response costs a scan its entire analysis.
      //
      // Only when a key is configured. Where none is set the deployment simply
      // does not have this feature, and saying so on every scan would be noise.
      if (process.env["DEEPSEEK_API_KEY"]) {
        scanResult.vulnerabilities.push({
          id: randomUUID(),
          name: "AI analysis could not be completed for this scan",
          severity: "info",
          category: "Scan Coverage",
          description:
            "Every security check ran and the findings below are complete — but the written analysis that normally accompanies them (the plain-English risk summary, the prioritised fixes and the per-agent fix prompts) could not be generated for this scan. The AI provider did not answer in time. This says nothing about your site: it is a gap in the explanation, not in the testing.",
          evidence: "The AI provider did not return an analysis within the 30-second budget.",
          solution:
            "Re-run the scan to get the written analysis. The findings themselves do not change — only the commentary on them is missing — so you can also act on the list below as it stands.",
          cweId: null,
          cvssScore: null,
          wstgId: null,
          confidence: 100,
        } satisfies ScanVulnerability);
      }
    }
  }

  // ── 5. Build report data ──────────────────────────────────────────────
  const riskScore = computeRiskScore(scanResult.vulnerabilities);
  // A scan a bot-protection layer answered must NOT be graded — see
  // gradeForResult. The score stays computed and stored for the record; the
  // grade becomes the sentinel the report and dashboard render as "coverage
  // incomplete".
  const intercepted = scanResult.intercepted;
  const grade = gradeForResult(riskScore, intercepted);

  const severityCounts = scanResult.vulnerabilities.reduce(
    (acc, v) => {
      acc[v.severity] = (acc[v.severity] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const executiveSummary = intercepted
    ? `The scan of ${(() => { try { return new URL(targetUrl).hostname; } catch { return targetUrl; } })()} ` +
      `was answered by a bot-protection layer rather than the site itself, so no grade could be assigned. ` +
      `Only the checks that do not read the page response — DNS, email authentication and mail transport — ` +
      `are reported below and are accurate; everything else was withheld. This is an incomplete result, not a ` +
      `clean one. To grade the site, allow the scanner through the challenge (by source IP or User-Agent) or ` +
      `verify domain ownership, then re-scan.`
    : buildExecutiveSummary(
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
    // What ran, what was skipped and why — so the report can show coverage,
    // not just findings. See testLedger.ts.
    tests,
    summary: {
      totalVulnerabilities: scanResult.vulnerabilities.length,
      critical: severityCounts["critical"] ?? 0,
      high: severityCounts["high"] ?? 0,
      medium: severityCounts["medium"] ?? 0,
      low: severityCounts["low"] ?? 0,
      info: severityCounts["info"] ?? 0,
      riskScore,
      grade,
      intercepted,
      executiveSummary,
    },
    recon: reconRunResult?.recon ?? undefined,
    aiAnalysis: aiAnalysis ?? undefined,
    // Which controls these findings are evidence FOR — not a compliance verdict.
    // Computed here so the mapping is frozen into the stored report alongside the
    // findings it describes: re-deriving it at render time would let a later
    // change to the mapping silently restate what an already-delivered report
    // said. See lib/compliance.ts, and COMPLIANCE_DISCLAIMER, which any view of
    // this data must carry.
    compliance: {
      frameworks: summariseCompliance(scanResult.vulnerabilities),
      disclaimer: COMPLIANCE_DISCLAIMER,
    },
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

    // ── 8. Update monitor subscription + write score history + detect regressions ──
    if (monitorSubscriptionId) {
      try {
        // Fetch current subscription for webhook URL and email
        const [sub] = await db
          .select()
          .from(monitorSubscriptionsTable)
          .where(eq(monitorSubscriptionsTable.id, monitorSubscriptionId))
          .limit(1);

        const gradeCadenceAt = computeNextScanAt(grade, completedAt);
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
            const newRegressions =
              newlyRun.length > 0
                ? []
                : scanResult.vulnerabilities.filter(
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

    // ── 9. Send report-ready email ────────────────────────────────────
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
  }
}

/**
 * A scan that failed gives back what paid for it — a bought credit, or one of
 * the subscription's included scans. Customers were previously charged for
 * scans the system never delivered. Idempotent (see refundFailedScan), and
 * never throws: the scan has already failed for its own reason, and a refund
 * error must not bury that.
 */
async function refundIfPaid(scanId: string, log: { info: (o: object, m: string) => void; error: (o: object, m: string) => void }): Promise<void> {
  try {
    const refunded = await refundFailedScan(scanId);
    if (refunded) log.info({ scanId, refunded }, "Refunded the payment for a failed scan");
  } catch (err) {
    log.error({ err, scanId }, "Could not refund a failed scan — needs manual credit");
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
    // Not "passed all security checks": a scan with skipped tests has not checked those areas,
    // and a clean grade says nothing about them. The report's coverage section lists them.
    return `${domain} has a grade of ${grade}: the tests that ran found no significant vulnerabilities. That is not a statement about any area this scan did not test, which the report lists. Re-scan regularly.`;
  }

  const urgencyPhrase =
    critical > 0
      ? `${critical} critical issue${critical > 1 ? "s" : ""} requiring immediate attention`
      : high > 0
        ? `${high} high-severity issue${high > 1 ? "s" : ""} that should be addressed promptly`
        : `${totalVulns} security finding${totalVulns > 1 ? "s" : ""}, none of them critical or high`;
  const advice = critical + high > 0 ? " Review the findings below and fix the critical and high items first." : "";

  return `Security scan of ${domain} identified ${urgencyPhrase}, yielding an overall grade of ${grade} with a risk score of ${riskScore}/100.${advice}`;
}

export async function startWorker(): Promise<void> {
  // Log the effective OSV cache size so operators can confirm env var took effect
  logger.info(
    { osvCacheMaxSize: OSV_CACHE_MAX_SIZE, envVar: "OSV_CACHE_MAX_SIZE" },
    "[cveCheck] OSV cache initialised",
  );

  // Launch headless browser for SPA rendering (deep tier scans).
  // Non-fatal — scanner falls back to raw fetch if Chromium is unavailable.
  await initBrowser();

  // Close the browser cleanly on worker shutdown so Chromium doesn't linger.
  const shutdown = async () => { await closeBrowser(); process.exit(0); };
  process.once("SIGTERM", () => { void shutdown(); });
  process.once("SIGINT",  () => { void shutdown(); });

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

  // How many scans this worker process runs at once.
  //
  // Was a hard-coded 2, which made the whole product a two-lane road: with a
  // median scan of ~26s (p90 38s), 100 people scanning at launch meant 50 waves
  // and a ~22-minute wait for the last one — long enough that they conclude it
  // is broken and leave. Meanwhile the container sits at 0.23 GB of a 7.45 GB
  // limit, so the constraint was arbitrary rather than physical.
  //
  // 8 is deliberate, not maximal. A scan holds a headless Chromium plus
  // hundreds of sockets; at a few hundred MB each, 8 lands near 2 GB and leaves
  // roughly 3x headroom on this container. The failure mode of guessing too
  // high is an OOM kill that drops every in-flight scan at once, so this moves
  // in one step with room to observe rather than straight to the ceiling.
  //
  // Env-overridable so the next move needs no deploy: raise
  // SCAN_WORKER_CONCURRENCY, watch /sys/fs/cgroup/memory.current during a
  // burst, and only then raise it again. Total fleet capacity is
  // replicas x this number.
  const scanConcurrency = Math.max(1, Number(process.env.SCAN_WORKER_CONCURRENCY) || 8);
  logger.info({ scanConcurrency }, "Scan worker concurrency");

  await boss.work<ScanJobData>(SCAN_QUEUE, { localConcurrency: scanConcurrency }, async (jobs) => {
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

  // ── Stuck-scan cleanup ────────────────────────────────────────────────────
  // Fails and refunds scans whose job died without reaching a failure path.
  // See reapStuckScans. Every 15 minutes; schedule() upserts by name, so
  // replicas share one schedule.
  await boss.createQueue(STUCK_SCAN_QUEUE);
  await boss.schedule(STUCK_SCAN_QUEUE, "*/15 * * * *", {});
  await boss.work(STUCK_SCAN_QUEUE, async () => {
    const { failed, refunded } = await reapStuckScans();
    if (failed > 0) logger.warn({ failed, refunded }, "Failed and refunded scans that never finished");
  });

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

  // Drop expired out-of-band tokens and their interactions on the same daily
  // schedule, so a busy scanner does not accumulate them without bound.
  await boss.createQueue(OOB_PURGE_QUEUE);
  await boss.schedule(OOB_PURGE_QUEUE, "30 3 * * *", {});
  await boss.work(OOB_PURGE_QUEUE, async () => {
    await purgeExpiredOobTokens();
  });
}

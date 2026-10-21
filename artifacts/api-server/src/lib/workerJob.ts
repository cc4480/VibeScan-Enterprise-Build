import type { ScanResult } from "./scanner";
import { loadScanAuth } from "./workerCredentials";
import { repoOnlyAddress, isRepoOnlyScan } from "./repoOnlyScan";
import { processRepoOnlyJob } from "./workerRepoJob";
import { mergeSslLabs, mergeTlsCheck, mergeRecon, recordSideTests, sslLabsEnabled } from "./workerSideChecks";
import { refineFindings } from "./workerFilters";
import { runAiStage } from "./workerAi";
import { buildReport } from "./workerReport";
import { persistReport, refundIfPaid } from "./workerPersist";
import { db, scansTable } from "@workspace/db";
import { eq, and, ne } from "drizzle-orm";
import { type ScanJobData } from "./queue";
import { runScan } from "./scanner";
import { looksSignedOut } from "./scanCredentials";
import { runRecon } from "./recon";
import { activeProbesUnlocked } from "./activeProbeGate";
import { createLiveProgress } from "./liveProgress";
import { failVerificationForScan } from "./verifyFix";
import { checkSslLabs } from "./ssllabs";
import { inspectTls } from "./tlsCheck";
import { logger } from "./logger";
import type { Job } from "pg-boss";

/**
 * pg-boss worker — processes scan jobs from the queue.
 * Registered at startup by index.ts.
 *
 * Job lifecycle per scan:
 *   queued → scanning → analyzing → complete
 *              ↓ (on error)
 *            failed
 */

type ScanJob = Job<ScanJobData>;

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

  // A repository with no website (lib/repoOnlyScan.ts): none of the site work below applies to it.
  if (repoOnlyAddress(targetUrl)) {
    const repoAuth = await loadScanAuth(scanId, log);
    if (isRepoOnlyScan(targetUrl, repoAuth.scanRow?.githubRepoUrl)) {
      await processRepoOnlyJob({ scanId, userId, targetUrl, tier, githubAccessToken: repoAuth.githubAccessToken, log });
      return;
    }
  }

  // ── 2. Run header scan + TLS check in parallel ─────────────────────────
  const useSslLabs = sslLabsEnabled();
  log.info({ sslLabs: useSslLabs }, "Starting HTTP scan, TLS configuration check, and reconnaissance in parallel");

  const parallelStartedAt = Date.now();
  // The scanner's own TLS check (tlsCheck.ts) is a few handshakes; it never rejects.
  const tlsPromise = inspectTls(targetUrl).catch((err): Awaited<ReturnType<typeof inspectTls>> => {
    log.warn({ err }, "TLS configuration check failed (non-fatal)");
    return { status: "failed", reason: err instanceof Error ? err.message.slice(0, 200) : "unexpected error" };
  });
  // SSL Labs is off unless SSLLABS_ENABLED=true (Qualys's terms need their permission for commercial
  // use). When on, it is best-effort and can take up to 30 seconds — start it early.
  const sslLabsPromise = useSslLabs
    ? checkSslLabs(targetUrl).catch((err) => {
        log.warn({ err }, "SSL Labs check failed (non-fatal)");
        return null;
      })
    : Promise.resolve(null);

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

  let scanResult: ScanResult;
  let scanTimer: ReturnType<typeof setTimeout> | undefined;
  let scanAbort: AbortController | undefined;
  let auth: Awaited<ReturnType<typeof loadScanAuth>>;
  // Finished tests, saved as they happen so the progress page shows real ones.
  const live = createLiveProgress(scanId);
  try {
    // The race alone only stops waiting; runScan would carry on, and its probes would keep hitting
    // the target. Aborting the signal makes every scan request fail at once.
    const abort = new AbortController();
    scanAbort = abort;
    const scanTimeout = new Promise<never>((_, reject) => {
      scanTimer = setTimeout(() => {
        abort.abort();
        reject(new Error(`HTTP scan timed out after ${SCAN_HTTP_TIMEOUT_MS / 1000}s`));
      }, SCAN_HTTP_TIMEOUT_MS);
    });
    auth = await loadScanAuth(scanId, log);
    const { scanRow, httpCredentials, reauthenticate, secondaryCredentials, githubAccessToken } = auth;

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
          ...(githubAccessToken ? { githubAccessToken } : {}),
          ...(scanRow?.autoSecondAccount ? { autoSecondAccount: true } : {}),
          // If the target redirects elsewhere, active probing continues only on a host this user verified.
          verifyHost: (url: string) => activeProbesUnlocked(userId, url),
          signal: abort.signal,
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
    scanAbort?.abort(); // whatever failed, stop the scan's requests from carrying on
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
  } finally {
    clearTimeout(scanTimer);
  }

  // Wait for the TLS check and, when enabled, SSL Labs (both started in parallel with the header scan)
  log.info("Waiting for the TLS configuration check to complete");
  const tlsCheck = mergeTlsCheck(scanResult, await tlsPromise, log);
  const sslLabsResult = await sslLabsPromise;
  if (useSslLabs) mergeSslLabs(scanResult, sslLabsResult, log);

  // ── 2b. Merge reconnaissance results ─────────────────────────────────
  log.info("Waiting for reconnaissance to complete");
  const reconRunResult = await reconPromise;
  mergeRecon(scanResult, reconRunResult, log);

  const tests = await recordSideTests({ scanResult, sslLabsEnabled: useSslLabs, sslLabsResult, tlsCheck, reconRunResult, allowActiveProbes, parallelStartedAt, live, log });

  // ── 2c–2e. Merge duplicates, re-verify borderline findings, drop dismissed ones ──
  const autoSuppressedCount = await refineFindings({ scanResult, targetUrl, userId, httpCredentials: auth.httpCredentials, allowActiveProbes, log });

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
  const aiAnalysis = await runAiStage({ scanResult, targetUrl, tier, tests, userId, verificationId, log });

  // ── 5. Build report data ──────────────────────────────────────────────
  const { reportData, riskScore, grade, intercepted, severityCounts, executiveSummary } = await buildReport({
    scanResult, targetUrl, tests, reconRunResult, aiAnalysis, autoSuppressedCount,
  });

  // ── 6–7. Persist the report and mark the scan complete (workerPersist.ts) ────────────────────────
  await persistReport({
    scanId, userId, targetUrl, tier, verificationId, monitorSubscriptionId, scanResult, tests,
    reportData, riskScore, grade, intercepted, severityCounts, executiveSummary, log,
  });
}

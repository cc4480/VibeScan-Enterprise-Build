import type { ScanResult } from "./scanner";
import type { Log } from "./workerTypes";
import { db, dismissedFindingsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { toScanHttpCredentials } from "./scanCredentials";
import { runWithScanHttp } from "./http";
import { corroborateMerge } from "./scoring";
import { findingFingerprint, canonicalizeTargetUrl } from "./fingerprint";
import { reprobe } from "./reprobe";

/**
 * Refines the raw findings: merges duplicate root causes, re-verifies borderline ones, and drops
 * what the owner already dismissed. Mutates scanResult.vulnerabilities; returns how many were
 * auto-suppressed.
 */
export async function refineFindings(input: {
  scanResult: ScanResult;
  targetUrl: string;
  userId: string;
  httpCredentials: Awaited<ReturnType<typeof toScanHttpCredentials>>;
  log: Log;
  /** The scan's allowActiveProbes. The re-probe sends an active OPTIONS request only when this is true. */
  allowActiveProbes?: boolean;
}): Promise<number> {
  const { scanResult, targetUrl, userId, httpCredentials, log, allowActiveProbes = false } = input;
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
    () => reprobe(targetUrl, scanResult.vulnerabilities, log, { allowActiveProbes }),
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
  return autoSuppressedCount;
}

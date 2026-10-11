/**
 * Active security probes — HTTP-based checks run in parallel alongside the main header scan.
 * Each probe is independent and best-effort (failures are non-fatal).
 *
 * Covers: sensitive file exposure, HTTP methods, active CORS, open redirects,
 * robots.txt analysis, Subresource Integrity, error disclosure, HTTPS redirect,
 * rate limiting, directory listing, and clickjacking verification.
 */

import { type TestLedger, NOT_VERIFIED } from "./testLedger";
import type { ScanVulnerability } from "./scanner";
import { checkSensitiveFiles, checkRobotsTxt, checkSecurityTxt, checkDirectoryListing } from "./probesFiles";
import { checkHttpMethods, checkActiveCors, checkClickjacking, checkOpenRedirect } from "./probesHttp";
import { checkSRI } from "./probesSri";
import { checkErrorDisclosure, checkHttpsRedirect, checkRateLimiting } from "./probesPage";
import { checkSupabaseRLS } from "./probesSupabase";
export { checkSensitiveFiles, checkRobotsTxt, checkSecurityTxt, checkDirectoryListing } from "./probesFiles";
export { checkHttpMethods, checkActiveCors, checkClickjacking, checkOpenRedirect } from "./probesHttp";
export { checkSRI } from "./probesSri";
export { checkErrorDisclosure, checkHttpsRedirect, checkRateLimiting } from "./probesPage";
export { checkSupabaseRLS } from "./probesSupabase";

// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param allowActive  Whether the caller has established that the user may
 *   have offensive traffic sent to this target (see lib/activeProbeGate.ts).
 *   The probes below split on one question: would this look, to the target,
 *   like an ordinary visitor, or like someone testing them?
 *
 *   Fetching a path — even one nothing links to — is what every crawler on
 *   the internet does, so exposed files, robots.txt, security.txt, directory
 *   listings and error pages stay available for any target. Sending a crafted
 *   Origin, an unusual method, a redirect payload, or querying somebody's
 *   database does not, and waits for verification.
 */
export async function runAllProbes(
  targetUrl: string,
  html: string,
  allowActive: boolean,
  /**
   * Called with the name of each check that threw instead of answering.
   *
   * Without this, a check that failed was dropped by the `fulfilled` filter
   * below and the scan reported nothing from it — identical, to the reader and
   * to the grade, to a check that ran and found the site clean. The caller uses
   * these names to say plainly which checks did not complete, rather than
   * implying they passed. Optional so existing callers and tests are unaffected.
   */
  onFailure?: (checkName: string, reason: unknown) => void,
  /** Records each check's outcome for the per-test log (see testLedger.ts). */
  ledger?: TestLedger,
  /** The address the user asked to scan, when it differs from targetUrl because of a redirect. */
  requestedUrl?: string,
  /**
   * The page exactly as the server sent it, before any browser rendering. Subresource integrity is
   * read from this, not from `html`: a rendered page also holds scripts that tag loaders (Segment,
   * HubSpot, Google Tag Manager, FullStory) injected at run time, which the site owner did not write
   * and cannot pin a hash on. Defaults to `html`, which is the same thing when nothing was rendered.
   */
  authoredHtml?: string,
  /**
   * The site's own JavaScript (see collectFirstPartyJavaScript), for the checks that read a backend's
   * address and keys. A production build keeps those in the bundle, not in the page, so a check that
   * is given only `html` finds nothing to test. A promise so the checks that do not need it start at
   * once while the scripts download.
   */
  siteCode?: Promise<string> | string,
): Promise<ScanVulnerability[]> {
  const passive: Array<[string, Promise<ScanVulnerability[]>]> = [
    ["sensitive file exposure", checkSensitiveFiles(targetUrl)],
    ["robots.txt disclosure", checkRobotsTxt(targetUrl)],
    ["subresource integrity", checkSRI(authoredHtml ?? html, targetUrl, requestedUrl)],
    ["verbose error pages", checkErrorDisclosure(targetUrl)],
    ["HTTP to HTTPS redirect", checkHttpsRedirect(targetUrl)],
    // Header heuristic only — the behavioural burst lives in apiProbe.ts and
    // is gated there.
    ["rate-limit headers", checkRateLimiting(targetUrl)],
    ["clickjacking headers", checkClickjacking(targetUrl)],
    ["directory listing", checkDirectoryListing(targetUrl)],
    ["security.txt", checkSecurityTxt(targetUrl)],
  ];

  // The page plus the site's own scripts, for the Supabase check only: the other checks do not wait for the scripts.
  const pageAndScripts = async () => {
    try { return `${html}\n${(await siteCode) ?? ""}`; } catch { return html; }
  };

  // Checks that can say they had nothing to test; read once the check settles.
  const supabaseNotTested: { value?: string } = {};
  const notTestedReasons = new Map([["Supabase RLS", supabaseNotTested]]);

  const active: Array<[string, Promise<ScanVulnerability[]>]> = allowActive
    ? [
        ["HTTP methods", checkHttpMethods(targetUrl)],
        ["active CORS", checkActiveCors(targetUrl)],
        ["open redirect", checkOpenRedirect(targetUrl)],
        // Reads rows out of the target's Supabase instance.
        ["Supabase RLS", checkSupabaseRLS(pageAndScripts(), (r) => { supabaseNotTested.value = r; })],
      ]
    : [];

  const all = [...passive, ...active];
  if (ledger && !allowActive) {
    for (const name of ["HTTP methods", "active CORS", "open redirect", "Supabase RLS"]) {
      ledger.skip("HTTP probes", name, NOT_VERIFIED);
    }
  }
  const settled = await Promise.allSettled(
    all.map(([name, p]) => {
      if (!ledger) return p;
      const reason = notTestedReasons.get(name);
      return reason
        ? ledger.trackOutcome("HTTP probes", name, p.then((findings) => ({ findings, notTested: reason.value })))
        : ledger.track("HTTP probes", name, p);
    }),
  );

  const findings: ScanVulnerability[] = [];
  settled.forEach((r, i) => {
    if (r.status === "fulfilled") {
      findings.push(...r.value);
      return;
    }
    onFailure?.(all[i]![0], r.reason);
  });

  return findings;
}
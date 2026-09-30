import { vuln, type ScanVulnerability } from "./scannerTypes";

/**
 * Finding raised when the scan's session expired partway through.
 *
 * Not a vulnerability in the target, but the user has to know: after the
 * session dropped, every "nothing found" means "not looked at" rather than
 * "looked at and clean", and a report that hid that would be misleading.
 */
export function sessionLostFinding(): ScanVulnerability {
  return vuln({
    name: "Scan session expired before the scan finished",
    severity: "info",
    category: "Scan Coverage",
    description:
      "The credentials you supplied stopped working partway through this scan — the target began returning its sign-in page. Pages checked after that point were seen signed out, so results for the authenticated part of the app are incomplete. This is a limitation of the scan, not a vulnerability in your site.",
    evidence: "One or more responses matched the target's signed-out page while credentials were in use.",
    solution:
      "Re-run the scan with a longer-lived session. A sign-in with a username and password can renew itself automatically; a pasted cookie or token cannot, so prefer form login for long scans, or supply a token with a longer expiry.",
    confidence: 95,
  });
}

/**
 * Finding raised when the scan ran without offensive probes.
 *
 * Same reasoning as sessionLostFinding: a report that quietly omitted half the
 * checks would read as a clean bill of health. The user has to know that the
 * injection, traversal, access-control and backend-exposure checks did not run
 * at all — those are where the severe findings come from, and their absence
 * here says nothing about whether the target has them.
 */
/**
 * Emitted when the target's edge served a challenge instead of the site.
 *
 * Without this the report is quietly wrong rather than visibly incomplete:
 * every content-derived check describes the interstitial, so the customer reads
 * findings about Cloudflare's HTML with their own domain at the top.
 */
export function interceptedFinding(vendor: string | null, signal: string): ScanVulnerability {
  return vuln({
    name: "Scan was intercepted by a bot-protection challenge",
    severity: "info",
    category: "Scan Coverage",
    description:
      `The request for this page was answered by ${vendor ? `${vendor}'s` : "an edge"} bot-protection layer rather than by the site itself, so what was analysed is the challenge page. Every check that reads the response — security headers, cookies, Content-Security-Policy, CORS, Subresource Integrity, structured data, third-party scripts — would have described that challenge page rather than this site, so those findings have been withheld rather than reported against you. What remains is what the interception could not affect: DNS and email authentication records, and mail transport security. This scan should not be read as a clean result.`,
    evidence: signal,
    solution:
      "Allow the scanner through the bot-protection rules for the duration of a scan — by source IP, or by User-Agent — then scan again. Verifying domain ownership also lets the scan authenticate itself.",
    confidence: 95,
  });
}

/**
 * Categories whose checks never read the intercepted response, so they remain
 * true about the target even when an edge answered instead of the origin.
 */
const SOURCES_NOT_READING_THE_RESPONSE = new Set([
  "Email Security",
  "DNS Security",
  "Mail Transport Security",
  "Scan Coverage",
]);

/**
 * Drops findings that were read from a bot-protection interstitial.
 *
 * Naming them as untrusted in a Scan Coverage note was not enough: the report
 * still said "etsy.com is missing Content-Security-Policy and serves a wildcard
 * CORS policy", which describes Cloudflare's challenge page and is false about
 * Etsy. Twelve of eighteen findings on that scan came from a page Etsy never
 * served.
 *
 * An allowlist, not a denylist, and deliberately so. The question is not which
 * findings look content-derived, but which sources did not read the intercepted
 * response at all. Over-suppressing behind an aggressive WAF costs a finding;
 * under-suppressing attributes another company's error page to the customer,
 * which this audit has repeatedly found to be the more expensive error.
 */
export function withholdInterceptedFindings(
  findings: ScanVulnerability[],
  isChallenge: boolean,
): ScanVulnerability[] {
  if (!isChallenge) return findings;
  return findings.filter((v) => SOURCES_NOT_READING_THE_RESPONSE.has(v.category));
}

export function activeProbesSkippedFinding(redirectedTo?: string): ScanVulnerability {
  return vuln({
    name: "Active security testing was skipped for this scan",
    severity: "info",
    category: "Scan Coverage",
    description:
      "This scan checked only what an ordinary visitor can observe: response headers, TLS, cookies, DNS, exposed files and known-vulnerable versions. The checks that actively test for flaws — SQL injection, cross-site scripting, path traversal, broken access control, SSRF, and exposed Supabase/Firebase data — were not run, because they send real attack traffic and we only do that against a domain whose owner has asked us to. A clean result here does not mean those flaws are absent; it means they were not looked for.",
    evidence: redirectedTo
      ? `The address you submitted redirected to ${redirectedTo}, which you have not verified, so active testing was withdrawn rather than sent to a site you may not own.`
      : "No verified ownership on record for this domain at scan time.",
    solution:
      "Verify that you control this domain — add the DNS TXT record or publish the verification file shown on your dashboard — then run the scan again to include active testing.",
    confidence: 100,
  });
}

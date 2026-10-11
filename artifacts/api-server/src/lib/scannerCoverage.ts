import { vuln, type ScanVulnerability } from "./scannerTypes";
import { PLAINTEXT_FINDING_NAME } from "./scannerTransportChecks";
import type { TestRecord } from "./testLedger";

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
  return splitInterceptedFindings(findings, isChallenge).kept;
}

/** A finding the scan produced and chose not to report, with the reason. Shown in the report. */
export interface WithheldFinding {
  name: string;
  severity: ScanVulnerability["severity"];
  category: string;
  reason: string;
}

/**
 * withholdInterceptedFindings, keeping what it dropped so the report can list it. A withheld
 * finding is not deleted silently: the reader sees its name and why it was not reported.
 */
export function splitInterceptedFindings(
  findings: ScanVulnerability[],
  isChallenge: boolean,
): { kept: ScanVulnerability[]; dropped: ScanVulnerability[] } {
  if (!isChallenge) return { kept: findings, dropped: [] };
  const kept: ScanVulnerability[] = [];
  const dropped: ScanVulnerability[] = [];
  for (const v of findings) (SOURCES_NOT_READING_THE_RESPONSE.has(v.category) ? kept : dropped).push(v);
  return { kept, dropped };
}

/**
 * Tests that never read the intercepted response: they ask DNS, the mail servers or a code
 * repository, so a sign-in wall or bot challenge in front of the site does not change what they saw.
 */
const TESTS_NOT_READING_THE_RESPONSE = new Set([
  "DNS and email authentication",
  "mail transport security (STARTTLS, MX certificate)",
  "subdomain takeover",
  "GitHub source code secrets",
]);

/**
 * On an intercepted scan, every other test that "ran" ran against the page that answered instead
 * of the app, and its findings are withheld. Left as "ran, 0 findings" it would tell the reader the
 * app was checked and came back clean, which is the opposite of what happened. Rewritten in place
 * to "skipped" with the reason, so the coverage list matches the withheld list.
 */
export function markInterceptedTestsNotRun(records: TestRecord[], reason: string): void {
  for (const r of records) {
    if (r.status !== "ran" || TESTS_NOT_READING_THE_RESPONSE.has(r.name)) continue;
    r.status = "skipped";
    r.reason = `not tested on the app: ${reason}`;
    r.findings = 0;
    delete r.found;
  }
}

export function withheldEntry(v: ScanVulnerability, reason: string): WithheldFinding {
  return { name: v.name, severity: v.severity, category: v.category, reason };
}

/**
 * Emitted when the scan reached a hosting platform's or identity provider's page instead of the app
 * (see platformGate.ts). Same treatment as a bot challenge: what was analysed is not the app, so
 * every finding read from it is withheld and the scan is not graded.
 */
export function platformGateFinding(kind: "sign-in wall" | "app not running", vendor: string | null, signal: string): ScanVulnerability {
  const who = vendor ?? "the hosting platform";
  const signIn = kind === "sign-in wall";
  return vuln({
    name: signIn ? "Scan reached a sign-in page, not the app" : "The hosting platform answered, not the app",
    severity: "info",
    category: "Scan Coverage",
    description:
      (signIn
        ? `Every request for this address was sent to a sign-in page run by ${who}, so the scan never saw the app behind it. `
        : `This address was answered by ${who}'s own page saying no app is running here (not found, paused, suspended or failing to start), so the scan never saw the app. `) +
      "That page looks the same for every site on the platform, so every check that reads the response (security headers, cookies, Content-Security-Policy, CORS, page content, exposed files, API tests) would have described it rather than your app. " +
      "Those findings have been withheld and listed under \"Withheld from this report\" instead. What remains is what does not depend on the page: DNS and email records. This is an incomplete result, not a clean one.",
    evidence: signal,
    solution: signIn
      ? "Scan an address that serves the app without signing in, or supply a login for the scan (Scan credentials). For Vercel Deployment Protection, scan the production domain or use a protection-bypass token."
      : "Check that the app is deployed and running at this address, then scan again.",
    confidence: 95,
  });
}

/** The address answered an error status, so what was analysed is an error response, not a page. */
export function rootErrorFinding(status: number, url: string): ScanVulnerability {
  return vuln({
    name: "Scan started from an error response",
    severity: "info",
    category: "Scan Coverage",
    description:
      `The page this scan started from answered HTTP ${status}${status >= 500 ? " (a server error)" : status === 401 || status === 403 ? " (sign-in or permission required)" : status === 404 ? " (not found)" : ""}. ` +
      "Header, cookie and page findings read from that response describe an error page, which may not be what visitors to the working app receive, so they are reported as information only and do not count towards the grade. " +
      "This is not a finding about your site on its own; it is here so a report built from an error page is not mistaken for one built from the app.",
    evidence: `GET ${url} → HTTP ${status}`,
    solution: status >= 500
      ? "Check the app is up, then scan again."
      : "Scan the address visitors actually land on, or supply a login (Scan credentials) if the app requires one.",
    confidence: 100,
  });
}

/**
 * Findings read from the response of a start page that answered an error status, reported as information.
 *
 * An error page is not the app: it often lacks the headers and cookies the app sets and carries no
 * structured data or Open Graph tags, so "Missing Content-Security-Policy (HIGH)" read from a 502 page is
 * a claim about the page the proxy served, not about the site. The findings are kept, because they may well
 * be true, but they are shown as information so they cannot be graded as the site's, and the note from
 * rootErrorFinding says so. A scheme problem is a fact about the address, not about the response, so
 * "No HTTPS / Plaintext HTTP" keeps its severity.
 *
 * A refusal with almost no body (403, 406, 429...) is handled earlier, as an interception, and withheld.
 */
export function capFindingsReadFromErrorPage(findings: ScanVulnerability[], status: number): ScanVulnerability[] {
  return findings.map((v) => {
    if (v.severity === "info" || v.name === PLAINTEXT_FINDING_NAME) return v;
    return {
      ...v,
      severity: "info",
      cvssScore: 0,
      confidence: Math.min(v.confidence ?? 100, 40),
      description: `${v.description}\n\nReported as information only: the page this scan started from answered HTTP ${status}, so this describes that error response and may not describe the working app (it was ${v.severity} before the cap).`,
    };
  });
}

/** The scan followed redirects onto a different site. Findings are kept; the reader is told whose they are. */
export function landedElsewhereFinding(requestedUrl: string, finalUrl: string): ScanVulnerability {
  return vuln({
    name: "Scan followed a redirect to a different site",
    severity: "info",
    category: "Scan Coverage",
    description:
      `${requestedUrl} redirected to ${finalUrl}. Header, cookie and page findings in this report were read from that site's response. ` +
      "If it is yours (another domain you own), they apply to you; if it is not, scan the address that serves your app instead.",
    evidence: `${requestedUrl} → ${finalUrl}`,
    solution: "Scan the address your app is actually served from.",
    confidence: 100,
  });
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

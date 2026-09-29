/**
 * Black-box HTTP security scanner.
 *
 * Stage 1 (this file): Fetches the target URL, analyses response headers,
 * cookies, TLS, CORS, and page content — produces an initial vulnerability list.
 *
 * Stage 2 (parallel, via worker.ts): SSL Labs TLS assessment.
 *
 * Stage 3 (parallel probes): Active HTTP probes via probes.ts,
 * DNS security checks via dnsChecks.ts, and JavaScript secret scanning
 * via jsScanner.ts — all run concurrently with stage 2.
 */

import { randomUUID } from "node:crypto";
import { detectChallengePage } from "./challengePage.js";
import { isLikelySessionCookie, requiresHttpOnly } from "./cookieClassification.js";

/**
 * Checks whether a hostname appears to be on the HSTS preload list.
 *
 * Uses the hstspreload.org submission-tracking API. Note: this API only knows
 * about domains submitted through their website. Domains hardcoded in Chrome's
 * preload list (google.com, youtube.com, etc.) are not tracked there and will
 * return "unknown". For those, we fall back to a behavioral signal: if the
 * HTTP version of the domain serves content without redirecting to HTTPS, the
 * site is likely relying on browser preloading.
 *
 * Returns true to SUPPRESS the HSTS finding; false to allow it (at MEDIUM).
 * Always fails-safe: any network error returns false so the check still runs.
 */
// Domains hardcoded in Chrome's built-in HSTS preload list that are NOT
// tracked by hstspreload.org's submission API (which only knows about
// user-submitted entries, not Chrome's built-in set).
const CHROME_BUILTIN_PRELOADED = new Set([
  "google.com", "youtube.com", "gmail.com", "android.com", "appspot.com",
  "blogger.com", "chromium.org", "googleapis.com", "googlesyndication.com",
  "googleusercontent.com", "gstatic.com", "ytimg.com", "doubleclick.net",
  "apple.com", "icloud.com", "github.com", "github.io", "githubusercontent.com",
  "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
  "linkedin.com", "microsoft.com", "live.com", "outlook.com", "office.com",
  "paypal.com", "amazon.com", "stripe.com", "cloudflare.com",
  "wordpress.com", "shopify.com", "dropbox.com", "box.com",
  "tumblr.com", "medium.com", "reddit.com", "wikipedia.org",
]);

async function isHstsPreloaded(hostname: string): Promise<boolean> {
  const apex = hostname.replace(/^www\./, "");

  // Fast path: known Chrome built-in preloaded domains not tracked by hstspreload.org
  if (CHROME_BUILTIN_PRELOADED.has(apex)) return true;

  // ── hstspreload.org tracking API ─────────────────────────────────────────
  // This API only tracks domains submitted via their form. Domains natively
  // hardcoded in Chrome (google.com, youtube.com, etc.) return "unknown".
  let apiKnows = false;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5_000);
    const res = await fetch(
      `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(apex)}`,
      { signal: ctrl.signal },
    );
    clearTimeout(timer);
    if (res.ok) {
      const json = (await res.json()) as { status?: string };
      if (json.status === "preloaded") return true;  // confirmed on list
      if (json.status === "pending")   return false; // submitted, not yet live
      // status === "unknown" — domain may still be natively preloaded; fall through
      apiKnows = json.status === "preloaded" || json.status === "pending";
    }
  } catch { /* fall through */ }

  if (apiKnows) return false;

  // ── Behavioral fallback for natively preloaded domains ───────────────────
  // If http:// traffic automatically upgrades to https://, the domain is
  // enforcing HTTPS one way or another — suppress the HSTS finding.
  const httpRes = await scanFetch(`http://${apex}/`, { timeoutMs: 5_000 });
  if (httpRes?.finalUrl.startsWith("https://")) return true;

  return false;
}

import { runWithScanHttp, scanFetch, scanFetchOrThrow, sessionWasLost, type ScanCredentials as ScanHttpCredentials } from "./http";
import { runAllProbes } from "./probes";
import { TestLedger, NOT_VERIFIED, type TestRecord } from "./testLedger";
import { isOobConfigured } from "./oobServer";
import { checkDnsSecurity } from "./dnsChecks";
import { scanJavaScriptForSecrets, collectJavaScript } from "./jsScanner";
import { extractSystemPromptText } from "./aiFeatureProbe";
import { runPromptInjectionProbe } from "./promptInjectionProbe";
import { attemptAutoSecondAccount } from "./autoSecondAccount";
import { parseGithubRepoRef, scanGithubRepo, githubNotScannedReason } from "./githubSourceProbe";
import { runRaceConditionProbe } from "./raceConditionProbe";
import { crawlAndCheck } from "./crawler";
import { checkForKnownVulnerabilities, extractVersionedTechnologies } from "./cveCheck";
import { analyzeJwts } from "./jwtAnalysis";
import { checkSubdomainTakeover } from "./subdomainTakeover";
import { checkPathTraversal } from "./pathTraversal";
import { runInjectionProbes } from "./injectionProbe";
import { checkSourceMaps } from "./sourceMaps";
import { checkVibeStackSecurity } from "./vibeStackProbes";
import { autoEnrichConfidence } from "./scoring";
import { detectTechnologies } from "./techFingerprint";
import { runBaasProbes } from "./baasProbes";
import { runGraphqlProbe } from "./graphqlProbe";
import { runApiDocsProbe } from "./apiDocsProbe";
import { runHealthEndpointProbe } from "./healthEndpointProbe";
import { runNextjsProbe } from "./nextjsProbe";
import { runStorageProbe } from "./storageProbe";
import { runAccessControlProbes } from "./accessControlProbe";
import { collectApiSurface, runApiProbes } from "./apiProbe";
import { runSsrfProbes } from "./ssrfProbe";
import type { ApiEndpoint } from "./apiSurface";
import { isSpa, renderPage } from "./browser";
import type { ObservedRequest } from "./apiRuntime";
import { SCANNER_USER_AGENT } from "./appOrigin";

export interface ScanVulnerability {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  evidence?: string | null;
  solution: string;
  cweId?: string | null;
  cvssScore?: number | null;
  wstgId?: string | null;
  /** Confidence score 0–100: how certain we are this is a real finding, not a false positive */
  confidence?: number | null;
}

export interface ScanResult {
  targetUrl: string;
  finalUrl: string;
  statusCode: number;
  server: string | null;
  tlsGrade: string | null;
  technologies: string[];
  vulnerabilities: ScanVulnerability[];
  requestDurationMs: number;
  rawHeaders: Record<string, string>;
  /** URLs of inner pages actually fetched during the deep crawl (excludes the root URL) */
  pagesScanned: string[];
  /** High-value probe paths that returned HTTP 404 during the crawl (see CrawlResult.probedNotFound) */
  probedNotFound: string[];
  /** True when the root page was rendered via headless browser (SPA detected) */
  renderedWithBrowser?: boolean;
  /**
   * True when a bot-protection layer answered instead of the origin, so every
   * content-derived check described the challenge page and was withheld. The
   * consumer must NOT grade such a scan: the surviving findings (DNS, email,
   * mail transport) are real, but the absence of everything else is an artefact
   * of not being let in, not evidence the site is clean. See interceptedFinding.
   */
  intercepted: boolean;
  /**
   * Every test the scan was meant to run and its outcome — ran, skipped (with
   * the reason) or failed — with its time and finding count. See testLedger.ts.
   * Optional because early-exit paths (unreachable target) run no tests.
   */
  tests?: TestRecord[];
}

const FETCH_TIMEOUT_MS = 20_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

function headerVal(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  const key = Object.keys(headers).find((k) => k.toLowerCase() === lower);
  return key ? headers[key] : undefined;
}

// detectTechnologies extracted to techFingerprint.ts

// Cookies set by third-party infrastructure (CDN proxies, load balancers, etc.)
// that the site owner has no ability to modify.  Flagging these produces
// unfixable false positives — the fix would require contacting the infra vendor.
const INFRA_COOKIE_NAMES = new Set([
  "gaesa",        // Replit CDN / proxy
  "__cf_bm",      // Cloudflare Bot Management
  "__cflb",       // Cloudflare Load Balancing
  "_cfuvid",      // Cloudflare UVID
  "cf_clearance", // Cloudflare challenge clearance
  "__utmz",       // Google Analytics (legacy)
  "__utma",       // Google Analytics (legacy)
  "_ga",          // Google Analytics
  "_gid",         // Google Analytics
  "_gat",         // Google Analytics throttle
  "bm_sz",        // Akamai Bot Manager — set by CDN, not the site operator
  "bm_sv",        // Akamai Bot Manager session
  "ak_bmsc",      // Akamai Bot Manager session cookie
  "_abck",        // Akamai Bot Manager
]);

// Cookies whose name suggests they actually carry session/auth state — a
// missing Secure/HttpOnly/SameSite flag on one of these is a real
// session-hijack or CSRF risk. Cookies that DON'T match (UI-state flags like
// "logged_in=yes", analytics/tracking IDs like "_octo" or "_ga") pose much
// less real-world risk since there's no session to steal or forge, so they're
// reported as a separate, lower-severity finding instead of being lumped in
// with genuine session cookies. Without this split, a scan of any site that
// merely sets a non-sensitive marker cookie (which is extremely common —
// e.g. GitHub's "logged_in" flag) gets penalized as if it leaked a session
// token.
// Takes the ALREADY-SPLIT cookie list from the fetch layer (getSetCookie()),
// not the flattened header string.
//
// Re-splitting a joined header on /\n|,(?=[^;])/ produced false positives.
// A Set-Cookie value legitimately contains a comma inside its expires date --
// "expires=Tue, 09-Mar-2027" -- and that comma is followed by a space, which
// matches [^;]. The cookie was sheared in half and every attribute AFTER the
// date became invisible:
//
//   NID=abc; expires=Tue, 09-Mar-2027 ...; HttpOnly
//     -> "NID=abc; expires=Tue"        <- analysed as the whole cookie
//     -> " 09-Mar-2027 ...; HttpOnly"  <- discarded, no "=" in first segment
//
// google.com's NID was reported as "Readable by JavaScript" when it does carry
// HttpOnly. That hits any cookie whose expires= precedes its security flags,
// which is most of them.
//
// The fallback keeps the old behaviour only where getSetCookie is unavailable.
function analyzeCookies(setCookies: string[], flattenedFallback?: string): ScanVulnerability[] {
  const cookies = setCookies.length > 0
    ? setCookies
    : (flattenedFallback ? flattenedFallback.split(/\n|,(?=[^;])/) : []);
  if (cookies.length === 0) return [];

  // Collect affected cookie names per problem type instead of emitting one
  // finding per cookie — a site that sets 10 cookies should not score 10×
  // worse than a site that sets 1. Each type of misconfiguration is one issue.
  // Session-like and non-session cookies are tracked separately (see
  // SESSION_COOKIE_PATTERN above) since the real-world risk differs a lot.
  const noSecure: string[] = [];
  const noSecureOther: string[] = [];
  const noHttpOnly: string[] = [];
  const noHttpOnlyOther: string[] = [];
  const noSameSite: string[] = [];
  const noSameSiteOther: string[] = [];

  for (const cookie of cookies) {
    if (!cookie.trim()) continue;
    // Skip malformed Set-Cookie fragments that have no name=value pair.
    // These are date fragments produced when "expires=Wed, 03-Jan-2025" is
    // mis-split at the comma (the regex above can't distinguish that comma from
    // a multi-cookie separator). A valid Set-Cookie first segment MUST contain "=".
    const firstSegment = cookie.split(";")[0] ?? "";
    if (!firstSegment.includes("=")) continue;
    const namePart = firstSegment.split("=")[0]?.trim() ?? "cookie";

    // Skip cookies owned by third-party infrastructure — the site operator
    // cannot add Secure/HttpOnly/SameSite to cookies they don't set.
    if (INFRA_COOKIE_NAMES.has(namePart.toLowerCase())) continue;

    const isSession = isLikelySessionCookie(namePart);

    if (!/secure/i.test(cookie))   (isSession ? noSecure : noSecureOther).push(namePart);
    // A CSRF token is exempt from HttpOnly and only from HttpOnly: the page has
    // to read it to echo it back. It still needs Secure and SameSite.
    if (!/httponly/i.test(cookie) && requiresHttpOnly(namePart)) {
      (isSession ? noHttpOnly : noHttpOnlyOther).push(namePart);
    }
    if (!/samesite/i.test(cookie)) (isSession ? noSameSite : noSameSiteOther).push(namePart);
  }

  const findings: ScanVulnerability[] = [];

  if (noSecure.length > 0) {
    const list = noSecure.join(", ");
    const plural = noSecure.length > 1;
    findings.push(vuln({
      name: "Session Cookie Missing Secure Flag",
      severity: "high",
      category: "Session Management",
      description: `${noSecure.length} likely session/auth cookie${plural ? "s are" : " is"} set without the Secure flag (${list}). ${plural ? "They can" : "It can"} be transmitted over unencrypted HTTP connections, making ${plural ? "them" : "it"} susceptible to interception.`,
      evidence: `Affected cookie${plural ? "s" : ""}: ${list}`,
      solution: "Add the Secure attribute to all session cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
      cweId: "CWE-614",
      cvssScore: 6.5,
      wstgId: "WSTG-SESS-02",
    }));
  }

  if (noSecureOther.length > 0) {
    const list = noSecureOther.join(", ");
    const plural = noSecureOther.length > 1;
    findings.push(vuln({
      name: "Non-Session Cookie Missing Secure Flag",
      severity: "low",
      category: "Session Management",
      description: `${noSecureOther.length} cookie${plural ? "s" : ""} without an obvious session/auth purpose ${plural ? "are" : "is"} set without the Secure flag (${list}). These don't appear to carry authentication state, so the practical risk is low — but worth fixing for defense in depth.`,
      evidence: `Affected cookie${plural ? "s" : ""}: ${list}`,
      solution: "Add the Secure attribute to all cookies where practical: Set-Cookie: name=value; Secure; SameSite=Lax",
      cweId: "CWE-614",
      cvssScore: 3.1,
      wstgId: "WSTG-SESS-02",
      confidence: 70,
    }));
  }

  if (noHttpOnly.length > 0) {
    const list = noHttpOnly.join(", ");
    const plural = noHttpOnly.length > 1;
    findings.push(vuln({
      name: "Session Cookie Missing HttpOnly Flag",
      severity: "medium",
      category: "Session Management",
      description: `${noHttpOnly.length} likely session/auth cookie${plural ? "s are" : " is"} set without the HttpOnly flag (${list}), allowing client-side JavaScript to access ${plural ? "them" : "it"}. This can enable session theft via XSS.`,
      evidence: `Affected cookie${plural ? "s" : ""}: ${list}`,
      solution: "Add the HttpOnly attribute to all session cookies: Set-Cookie: name=value; HttpOnly; Secure; SameSite=Lax",
      cweId: "CWE-1004",
      cvssScore: 5.3,
      wstgId: "WSTG-SESS-02",
    }));
  }

  if (noHttpOnlyOther.length > 0) {
    const list = noHttpOnlyOther.join(", ");
    const plural = noHttpOnlyOther.length > 1;
    findings.push(vuln({
      name: "Non-Session Cookie Readable by JavaScript",
      severity: "info",
      category: "Session Management",
      description: `${noHttpOnlyOther.length} cookie${plural ? "s" : ""} without an obvious session/auth purpose ${plural ? "are" : "is"} readable by client-side JavaScript (${list}). Many such cookies (UI-state flags, analytics IDs) are intentionally client-readable, so this is informational unless the cookie actually holds sensitive data.`,
      evidence: `Affected cookie${plural ? "s" : ""}: ${list}`,
      solution: "If any of these cookies hold sensitive data, add HttpOnly. If they're purely UI-state or analytics markers, no action is needed.",
      cweId: "CWE-1004",
      cvssScore: 2.6,
      wstgId: "WSTG-SESS-02",
      confidence: 60,
    }));
  }

  if (noSameSite.length > 0) {
    const list = noSameSite.join(", ");
    const plural = noSameSite.length > 1;
    findings.push(vuln({
      name: "Session Cookie Missing SameSite Attribute",
      severity: "medium",
      category: "CSRF Protection",
      description: `${noSameSite.length} likely session/auth cookie${plural ? "s lack" : " lacks"} the SameSite attribute (${list}), making the application potentially vulnerable to Cross-Site Request Forgery (CSRF) attacks.`,
      evidence: `Affected cookie${plural ? "s" : ""}: ${list}`,
      solution: "Set SameSite=Lax or SameSite=Strict on all session cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
      cweId: "CWE-352",
      cvssScore: 4.3,
      wstgId: "WSTG-SESS-02",
    }));
  }

  if (noSameSiteOther.length > 0) {
    const list = noSameSiteOther.join(", ");
    const plural = noSameSiteOther.length > 1;
    findings.push(vuln({
      name: "Non-Session Cookie Missing SameSite Attribute",
      severity: "info",
      category: "CSRF Protection",
      description: `${noSameSiteOther.length} cookie${plural ? "s" : ""} without an obvious session/auth purpose ${plural ? "lack" : "lacks"} the SameSite attribute (${list}). Since these don't appear to gate authenticated actions, CSRF risk from them specifically is minimal.`,
      evidence: `Affected cookie${plural ? "s" : ""}: ${list}`,
      solution: "Set SameSite=Lax on these cookies where practical, though the CSRF risk here is low.",
      cweId: "CWE-352",
      cvssScore: 2.1,
      wstgId: "WSTG-SESS-02",
      confidence: 60,
    }));
  }

  return findings;
}

/**
 * Establishes the per-scan HTTP context (see lib/http.ts) and runs the scan
 * inside it, so every probe below this call shares one client, one User-Agent,
 * and one place where credentials are scoped to the target host.
 *
 * Split from the body only to avoid indenting the whole function.
 */
export interface RunScanAuth {
  credentials: ScanHttpCredentials;
  /**
   * A second account. Present only when the user supplied one, and the sole
   * trigger for access-control testing — the comparison needs two identities
   * that own different data.
   */
  secondary?: ScanHttpCredentials;
  /** Recognises a signed-out response. */
  detectSignedOut?: (body: string, finalUrl: string, requestedUrl: string) => boolean;
  /** Signs back in when the session expires mid-scan. */
  onSessionLost?: () => Promise<ScanHttpCredentials | null>;
}

/**
 * Optional, independent extras that do not belong on `RunScanAuth` — that
 * object only exists at all when the scan is authenticated against the
 * target, and both of these are meaningful on an unauthenticated scan too.
 * A new trailing optional parameter, so every existing call site (which
 * passes none of this) is entirely unaffected.
 */
export interface RunScanExtras {
  /**
   * A public GitHub repository ("owner/repo" or a full URL) to additionally
   * scan for hardcoded secrets in source, alongside the live-URL scan. See
   * githubSourceProbe.ts. Omitted entirely for most scans; this is opt-in
   * per scan, supplied by the user.
   */
  githubRepoUrl?: string;
  /**
   * Explicit, scan-by-scan opt-in for the active race-condition probe (see
   * raceConditionProbe.ts for why this is not on by default). Defaults to
   * false/omitted, meaning the probe never runs unless a caller sets this.
   */
  raceConditionTesting?: boolean;
}

export async function runScan(
  targetUrl: string,
  tier: string,
  // Whether the caller established that this user may have offensive traffic
  // sent to this target. Required rather than defaulted: a scan entry point
  // that forgets to decide should fail to compile, not quietly attack someone.
  allowActiveProbes: boolean,
  auth?: RunScanAuth,
  // Correlates out-of-band callbacks back to this scan. Optional so a monitor
  // rescan or a test can call runScan without one; SSRF detection is simply
  // skipped when it and a callback host are both absent.
  scanId?: string | null,
  // Hears each test the moment it is recorded, for the live progress page.
  onTest?: (record: TestRecord) => void,
  extra?: RunScanExtras,
): Promise<ScanResult> {
  // Credentials go into the scan context, where lib/http.ts attaches them only
  // to in-scope requests and drops them on any redirect that leaves the target.
  return runWithScanHttp(
    {
      targetUrl,
      ...(auth
        ? {
            credentials: auth.credentials,
            ...(auth.detectSignedOut ? { detectSignedOut: auth.detectSignedOut } : {}),
            ...(auth.onSessionLost ? { onSessionLost: auth.onSessionLost } : {}),
          }
        : {}),
    },
    () => runScanInner(targetUrl, tier, allowActiveProbes, auth, scanId ?? null, onTest, extra),
  );
}

/**
 * Finding raised when the scan's session expired partway through.
 *
 * Not a vulnerability in the target, but the user has to know: after the
 * session dropped, every "nothing found" means "not looked at" rather than
 * "looked at and clean", and a report that hid that would be misleading.
 */
function sessionLostFinding(): ScanVulnerability {
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
function interceptedFinding(vendor: string | null, signal: string): ScanVulnerability {
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

function activeProbesSkippedFinding(): ScanVulnerability {
  return vuln({
    name: "Active security testing was skipped for this scan",
    severity: "info",
    category: "Scan Coverage",
    description:
      "This scan checked only what an ordinary visitor can observe: response headers, TLS, cookies, DNS, exposed files and known-vulnerable versions. The checks that actively test for flaws — SQL injection, cross-site scripting, path traversal, broken access control, SSRF, and exposed Supabase/Firebase data — were not run, because they send real attack traffic and we only do that against a domain whose owner has asked us to. A clean result here does not mean those flaws are absent; it means they were not looked for.",
    evidence: "No verified ownership on record for this domain at scan time.",
    solution:
      "Verify that you control this domain — add the DNS TXT record or publish the verification file shown on your dashboard — then run the scan again to include active testing.",
    confidence: 100,
  });
}

async function runScanInner(
  targetUrl: string,
  tier: string,
  allowActiveProbes: boolean,
  auth?: RunScanAuth,
  scanId: string | null = null,
  onTest?: (record: TestRecord) => void,
  extra?: RunScanExtras,
): Promise<ScanResult> {
  const startedAt = Date.now();

  // The only request whose failure ends the scan, so it is the only one that
  // throws rather than returning null — the underlying reason is what the user
  // needs to see when a target is unreachable.
  let initial;
  try {
    initial = await scanFetchOrThrow(targetUrl, {
      timeoutMs: FETCH_TIMEOUT_MS,
      headers: {
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to reach target URL: ${msg}`);
  }

  let finalUrl = initial.finalUrl || targetUrl;
  let html = initial.body;

  // Keys arrive lowercased from the shared client. Every lookup already goes
  // through the case-insensitive helper above, so this is a no-op for callers.
  const rawHeaders: Record<string, string> = { ...initial.headers };

  // ── SPA detection + headless rendering ────────────────────────────────────
  // If the server returned a JS-shell SPA (empty <div id="root"> etc.), re-fetch
  // via headless browser so content analysis operates on the fully-rendered DOM.
  // HTTP security headers stay from the raw fetch above — they're identical.
  let renderedWithBrowser = false;
  let observedRequests: ObservedRequest[] = [];
  if (isSpa(html)) {
    const rendered = await renderPage(finalUrl).catch(() => null);
    if (rendered) {
      html = rendered.html;
      finalUrl = rendered.finalUrl || finalUrl;
      renderedWithBrowser = true;
      observedRequests = rendered.observed;
    }
  }

  const isHttps = finalUrl.startsWith("https://");
  const tlsGrade = isHttps ? "A" : null;
  const server = headerVal(rawHeaders, "server") ?? null;

  // Detect technologies and enrich with version numbers where available
  // e.g. "jQuery" → "jQuery 1.11.3", "Nginx" → "Nginx 1.18.0"
  const baseTechs = detectTechnologies(rawHeaders, html);
  const versionedTechs = extractVersionedTechnologies(html, rawHeaders);
  // Match by techName (canonical name from detectTechnologies) to avoid duplicates
  // e.g. "Apache HTTPD" techName="Apache" matches base tech "Apache" correctly
  const versionMap = new Map(versionedTechs.map((v) => [v.techName.toLowerCase(), v.version]));
  const technologies = baseTechs.map((tech) => {
    const ver = versionMap.get(tech.toLowerCase());
    return ver ? `${tech} ${ver}` : tech;
  });
  // Surface any additional versioned techs not already in the base list (by techName)
  const techNamesInBase = new Set(technologies.map((t) => t.split(" ")[0]?.toLowerCase()));
  for (const vt of versionedTechs) {
    if (!techNamesInBase.has(vt.techName.toLowerCase())) {
      technologies.push(`${vt.displayName} ${vt.version}`);
    }
  }

  const requestDurationMs = Date.now() - startedAt;
  const vulnerabilities: ScanVulnerability[] = [];

  // ── TLS / HTTPS ───────────────────────────────────────────────────────
  if (!isHttps) {
    vulnerabilities.push(vuln({
      name: "No HTTPS / Plaintext HTTP",
      severity: "critical",
      category: "Transport Security",
      description: "The application is served over HTTP without TLS encryption. All data transmitted between the browser and the server—including passwords and session tokens—can be intercepted by any network observer.",
      evidence: `URL: ${finalUrl}\nProtocol: HTTP (no TLS)`,
      solution: "Obtain a TLS certificate (free from Let's Encrypt) and redirect all HTTP traffic to HTTPS. Set up HSTS once HTTPS is working.",
      cweId: "CWE-319",
      cvssScore: 9.1,
      wstgId: "WSTG-CRYP-01",
    }));
  }

  // ── HTTP Strict-Transport-Security ────────────────────────────────────
  const hsts = headerVal(rawHeaders, "strict-transport-security");
  if (!hsts && isHttps) {
    // Before flagging: check the HSTS preload list. Preloaded domains have HTTPS
    // enforced in browsers before the first request, so the header is optional.
    // This also prevents false positives when the scanner runs behind a
    // TLS-terminating proxy that strips security headers from HTTPS responses.
    const preloaded = await isHstsPreloaded(new URL(finalUrl).hostname).catch(() => false);
    if (!preloaded) {
      // Since we successfully fetched this site over HTTPS, it clearly HAS HTTPS.
      // A missing STS header means browsers won't cache the HTTPS preference, but
      // HTTPS itself is working. This is MEDIUM (not HIGH). HIGH is reserved for
      // sites with no HTTPS at all (handled above). Some sites (e.g. google.com)
      // intentionally omit the header, relying on the HSTS preload list instead.
      vulnerabilities.push(vuln({
        name: "Missing HTTP Strict-Transport-Security (HSTS)",
        severity: "medium",
        category: "Transport Security",
        description: "HSTS is not configured via response header. Without it, browsers won't cache the HTTPS-only preference, leaving users vulnerable to downgrade attacks and SSL stripping on their first visit or after cache expiry. Note: some sites rely on HSTS preloading (browser built-in list) instead — verify at https://hstspreload.org.",
        evidence: `GET ${finalUrl}\nStrict-Transport-Security: (header absent from response)`,
        solution: "Add this header to all HTTPS responses: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\nFor the strongest protection, also submit your domain to the HSTS preload list at https://hstspreload.org",
        cweId: "CWE-523",
        cvssScore: 5.3,
        wstgId: "WSTG-CONF-07",
      }));
    }
  } else if (hsts) {
    // Check for weak HSTS config
    const maxAgeMatch = /max-age=(\d+)/i.exec(hsts);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    if (maxAge < 15552000) { // less than 180 days
      vulnerabilities.push(vuln({
        name: "HSTS max-age Too Short",
        severity: "low",
        category: "Transport Security",
        description: `The HSTS max-age is set to ${maxAge} seconds (${Math.round(maxAge / 86400)} days), which is below the recommended minimum of 180 days (15552000 seconds). Short max-age values mean users lose HTTPS protection shortly after their browser cache expires.`,
        evidence: `GET ${finalUrl}\nStrict-Transport-Security: ${hsts}\n(max-age=${maxAge} — minimum recommended: 15552000)`,
        solution: "Set max-age to at least 15552000 (180 days). For preloading eligibility, use max-age=31536000; includeSubDomains; preload.",
        cweId: "CWE-523",
        cvssScore: 3.1,
        wstgId: "WSTG-CONF-07",
      }));
    }
  }

  // ── Content-Security-Policy ───────────────────────────────────────────
  const csp = headerVal(rawHeaders, "content-security-policy");
  // A report-only policy is not enforcement — the browser reports the
  // violation and runs the script anyway — so its presence is still a finding.
  // But it is a different finding, and saying "header absent from response"
  // about a site plainly running a CSP in report-only mode is wrong, and reads
  // as a false positive to anyone who checks. google.com does exactly this.
  const cspReportOnly = headerVal(rawHeaders, "content-security-policy-report-only");
  if (!csp && cspReportOnly) {
    vulnerabilities.push(vuln({
      name: "Content-Security-Policy is report-only (not enforced)",
      severity: "medium",
      category: "Injection Defense",
      description:
        "A Content-Security-Policy is present but sent as Content-Security-Policy-Report-Only. In that mode the browser reports violations and still executes the offending script, so the policy provides no protection against Cross-Site Scripting — it only shows what a real policy would have blocked. This is the correct way to trial a policy, and is a problem only if it was meant to be enforcing.",
      evidence: `GET ${finalUrl}
Content-Security-Policy: (absent)
Content-Security-Policy-Report-Only: ${cspReportOnly.slice(0, 200)}`,
      solution:
        "Once the violation reports are clean, send the same policy as Content-Security-Policy to begin enforcing it. Sending both during the transition is fine.",
      cweId: "CWE-79",
      cvssScore: 5.3,
      wstgId: "WSTG-CONF-12",
    }));
  } else if (!csp) {
    vulnerabilities.push(vuln({
      name: "Missing Content-Security-Policy (CSP)",
      severity: "high",
      category: "Injection Defense",
      description: "No Content-Security-Policy header was found. CSP is the primary browser-enforced defense against Cross-Site Scripting (XSS) attacks. Without it, injected scripts can run with full page privileges and steal session cookies or credentials.",
      evidence: `GET ${finalUrl}\nContent-Security-Policy: (header absent from response)`,
      solution: "Implement a strict CSP. A starting point: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'. Tighten over time using CSP violation reports.",
      cweId: "CWE-79",
      cvssScore: 7.2,
      wstgId: "WSTG-CONF-12",
    }));
  } else {
    // Parse directives into a map so we can check WHICH directives contain
    // unsafe-inline / unsafe-eval.  This matters because:
    //   • unsafe-inline / unsafe-eval in script-src → MEDIUM (XSS, scripts execute)
    //   • unsafe-inline ONLY in style-src (script-src is clean) → LOW (CSS injection
    //     only — can spoof UI / exfiltrate via attribute selectors, but cannot run JS)
    const cspDirMap = new Map<string, string>();
    for (const seg of csp.split(";").map((s) => s.trim()).filter(Boolean)) {
      const spaceIdx = seg.indexOf(" ");
      const dname = spaceIdx === -1 ? seg : seg.slice(0, spaceIdx);
      const dval  = spaceIdx === -1 ? ""  : seg.slice(spaceIdx + 1);
      cspDirMap.set(dname.toLowerCase(), dval);
    }

    const defaultSrc      = cspDirMap.get("default-src") ?? "";
    const effectiveScript = cspDirMap.get("script-src") ?? defaultSrc;
    const effectiveStyle  = cspDirMap.get("style-src")  ?? defaultSrc;

    const scriptHasUnsafe = /unsafe-inline|unsafe-eval/i.test(effectiveScript);
    const styleOnlyUnsafe = /unsafe-inline/i.test(effectiveStyle) && !scriptHasUnsafe;

    if (scriptHasUnsafe) {
      vulnerabilities.push(vuln({
        name: "Weak Content-Security-Policy (unsafe-inline / unsafe-eval in script-src)",
        severity: "medium",
        category: "Injection Defense",
        description: "The Content-Security-Policy allows 'unsafe-inline' or 'unsafe-eval' in script-src (or default-src). This significantly weakens XSS protection — attackers who achieve HTML injection can execute arbitrary JavaScript in the page's security context.",
        evidence: `GET ${finalUrl}\nContent-Security-Policy: ${csp}\n(unsafe-inline or unsafe-eval present in script-src — inline script execution is permitted)`,
        solution: "Replace 'unsafe-inline' with nonce-based or hash-based CSP directives. Avoid 'unsafe-eval' entirely. Use a CSP evaluator (csp-evaluator.withgoogle.com) to audit your policy.",
        cweId: "CWE-79",
        cvssScore: 5.4,
        wstgId: "WSTG-CONF-12",
      }));
    } else if (styleOnlyUnsafe) {
      vulnerabilities.push(vuln({
        name: "Content-Security-Policy Allows Inline Styles (unsafe-inline in style-src)",
        severity: "low",
        category: "Injection Defense",
        description: "The Content-Security-Policy permits 'unsafe-inline' in style-src. Script execution is properly restricted (script-src has no unsafe-inline). CSS injection cannot execute JavaScript but can enable visual spoofing, clickjacking, and CSS-based data exfiltration via attribute selectors.",
        evidence: `GET ${finalUrl}\nContent-Security-Policy: ${csp}\n(unsafe-inline in style-src only — script-src is clean, no JS execution risk)`,
        solution: "For the strongest defence, replace style-src 'unsafe-inline' with nonce-based or hash-based directives. For Tailwind CSS builds, all styles compile to an external stylesheet in production — unsafe-inline can usually be removed once any remaining inline style= attributes are eliminated.",
        cweId: "CWE-79",
        cvssScore: 3.1,
        wstgId: "WSTG-CONF-12",
      }));
    }
  }

  // ── CSP deep analysis (when CSP exists) ──────────────────────────────
  if (csp) {
    // object-src 'none' prevents Flash/Java plugins and data: URI XSS escalation
    if (!/object-src\s+'none'/i.test(csp) && !/object-src\s+['"]\s*['"]/i.test(csp)) {
      const hasDefaultNone = /default-src\s+'none'/i.test(csp);
      if (!hasDefaultNone) {
        vulnerabilities.push(vuln({
          name: "CSP Missing object-src 'none' Directive",
          severity: "medium",
          category: "Injection Defense",
          description: "The Content-Security-Policy does not include 'object-src: none'. Without this, browsers may allow Flash, Java, or other plugin content to load, which can bypass script-src restrictions entirely. XSS via plugin content is a known CSP bypass technique.",
          evidence: `GET ${finalUrl}\nContent-Security-Policy: ${csp}\n(object-src directive absent — plugin content unrestricted)`,
          solution: "Add object-src 'none' to your CSP. If you use default-src 'none', object-src is implicitly restricted.",
          cweId: "CWE-79",
          cvssScore: 4.3,
          wstgId: "WSTG-CONF-12",
        }));
      }
    }

    // base-uri restriction prevents base-tag injection attacks
    if (!/base-uri/i.test(csp)) {
      vulnerabilities.push(vuln({
        name: "CSP Missing base-uri Directive",
        severity: "low",
        category: "Injection Defense",
        description: "The Content-Security-Policy does not restrict base-uri. Without this directive, an attacker who can inject a <base href='https://attacker.com'> tag can redirect all relative URLs on the page to their own server, hijacking resource loads and form submissions.",
        evidence: `GET ${finalUrl}\nContent-Security-Policy: ${csp}\n(base-uri directive absent)`,
        solution: "Add base-uri 'self' to your CSP to prevent base-tag injection attacks.",
        cweId: "CWE-79",
        cvssScore: 3.5,
        wstgId: "WSTG-CONF-12",
      }));
    }

    // A wildcard only defeats CSP when it allows ANY origin. The old check was
    // /script-src\s+[^;]*\*/ — any asterisk anywhere in the directive — which
    // fires on ordinary allowlist entries like https://*.onetrust.com or
    // *.google-analytics.com. Almost every CSP that loads analytics has one, so a
    // well-built policy was reported HIGH as "XSS Protection Bypassed":
    // cloudflare.com and mozilla.org both were, on CSPs listing ~20 named origins.
    //
    // A subdomain wildcard on a named, trusted domain is an allowlist entry, not a
    // bypass. Only a bare * (optionally scheme-prefixed) lets scripts load from
    // anywhere, so only that is reported.
    const scriptSrc = /script-src\s+([^;]*)/i.exec(csp)?.[1] ?? "";
    const allowsAnyOrigin = scriptSrc
      .split(/\s+/)
      .filter(Boolean)
      .some((src) => src === "*" || src === "*:" || /^(https?:)?\/\/\*$/i.test(src));
    if (allowsAnyOrigin) {
      vulnerabilities.push(vuln({
        name: "CSP script-src Contains Wildcard — XSS Protection Bypassed",
        severity: "high",
        category: "Injection Defense",
        description: "The script-src directive in the Content-Security-Policy contains a wildcard (*), which allows scripts to be loaded from any origin. This completely defeats the purpose of CSP as an XSS mitigation.",
        evidence: `GET ${finalUrl}\nContent-Security-Policy: ${csp}\n(wildcard in script-src allows scripts from any origin)`,
        solution: "Remove wildcards from script-src. Use an explicit allowlist of trusted origins, or switch to nonce-based CSP: script-src 'nonce-{random}'.",
        cweId: "CWE-79",
        cvssScore: 7.2,
        wstgId: "WSTG-CONF-12",
      }));
    }
  }

  // ── X-Frame-Options ───────────────────────────────────────────────────
  const xfo = headerVal(rawHeaders, "x-frame-options");
  const cspFrameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !cspFrameAncestors) {
    vulnerabilities.push(vuln({
      name: "Missing Clickjacking Protection (X-Frame-Options)",
      severity: "medium",
      category: "UI Security",
      description: "The application does not set X-Frame-Options or CSP frame-ancestors. Attackers can embed your pages in invisible iframes on malicious sites and trick users into clicking UI elements (clickjacking).",
      evidence: `GET ${finalUrl}\nX-Frame-Options: (header absent)\nCSP frame-ancestors: (not present in Content-Security-Policy)`,
      solution: "Add: X-Frame-Options: DENY (or SAMEORIGIN if you need to embed within your own domain). Alternatively use: Content-Security-Policy: frame-ancestors 'none'",
      cweId: "CWE-1021",
      cvssScore: 4.3,
      wstgId: "WSTG-CLNT-09",
    }));
  }

  // ── X-Content-Type-Options ────────────────────────────────────────────
  const xcto = headerVal(rawHeaders, "x-content-type-options");
  if (!xcto || xcto.toLowerCase() !== "nosniff") {
    vulnerabilities.push(vuln({
      name: "Missing X-Content-Type-Options: nosniff",
      severity: "medium",
      category: "Content Sniffing",
      description: "The X-Content-Type-Options header is absent or not set to 'nosniff'. Browsers may MIME-sniff response content and execute it as a different content type, enabling content-injection attacks.",
      evidence: xcto
        ? `GET ${finalUrl}\nX-Content-Type-Options: ${xcto}\n(must be exactly "nosniff")`
        : `GET ${finalUrl}\nX-Content-Type-Options: (header absent from response)`,
      solution: "Add to all responses: X-Content-Type-Options: nosniff",
      cweId: "CWE-16",
      cvssScore: 4.3,
      wstgId: "WSTG-CONF-07",
    }));
  }

  // ── Referrer-Policy ───────────────────────────────────────────────────
  const rp = headerVal(rawHeaders, "referrer-policy");
  if (!rp) {
    vulnerabilities.push(vuln({
      name: "Missing Referrer-Policy Header",
      severity: "low",
      category: "Information Disclosure",
      description: "No Referrer-Policy header is set. By default, browsers may include the full URL of the previous page in the Referer header, potentially leaking sensitive URL parameters (session tokens, search queries) to third-party sites.",
      evidence: `GET ${finalUrl}\nReferrer-Policy: (header absent from response)`,
      solution: "Add: Referrer-Policy: strict-origin-when-cross-origin (or 'no-referrer' for maximum privacy)",
      cweId: "CWE-200",
      cvssScore: 3.1,
      wstgId: "WSTG-CONF-07",
    }));
  }

  // ── Permissions-Policy ────────────────────────────────────────────────
  const pp = headerVal(rawHeaders, "permissions-policy") ?? headerVal(rawHeaders, "feature-policy");
  if (!pp) {
    vulnerabilities.push(vuln({
      name: "Missing Permissions-Policy Header",
      severity: "low",
      category: "Browser Feature Control",
      description: "No Permissions-Policy (formerly Feature-Policy) header is present. This header restricts which browser APIs (camera, microphone, geolocation, etc.) can be accessed from your pages and embedded iframes.",
      evidence: `GET ${finalUrl}\nPermissions-Policy: (header absent from response)`,
      solution: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=(). Adjust based on what your app actually needs.",
      cweId: "CWE-16",
      cvssScore: 2.4,
      wstgId: "WSTG-CONF-07",
    }));
  }

  // ── Cross-Origin isolation headers (COOP / COEP / CORP) ─────────────
  // These headers enable cross-origin isolation, which is required to safely
  // use SharedArrayBuffer and high-resolution timers. Most public-facing web
  // apps don't use these APIs and don't need full isolation — absence is
  // therefore informational, not a direct vulnerability. Flag as INFO so
  // teams can make an informed choice rather than reflexively chasing headers.
  const coop = headerVal(rawHeaders, "cross-origin-opener-policy");
  if (!coop) {
    vulnerabilities.push(vuln({
      name: "Missing Cross-Origin-Opener-Policy (COOP)",
      severity: "info",
      category: "Browser Feature Control",
      description: "The Cross-Origin-Opener-Policy header is not set. COOP isolates your browsing context from cross-origin popups, preventing other pages from accessing your window object. It is required to safely enable SharedArrayBuffer and high-resolution timers. Most public web apps do not need these APIs, so absence is typically informational — but enabling COOP is a free defence-in-depth measure.",
      evidence: `GET ${finalUrl}\nCross-Origin-Opener-Policy: (header absent from response)`,
      solution: "Add: Cross-Origin-Opener-Policy: same-origin (most secure) or same-origin-allow-popups if you need cross-origin popup interaction. Only required if you use SharedArrayBuffer or high-resolution timers.",
      cweId: "CWE-346",
      wstgId: "WSTG-CONF-07",
    }));
  }

  const coep = headerVal(rawHeaders, "cross-origin-embedder-policy");
  if (!coep) {
    vulnerabilities.push(vuln({
      name: "Missing Cross-Origin-Embedder-Policy (COEP)",
      severity: "info",
      category: "Browser Feature Control",
      description: "The Cross-Origin-Embedder-Policy header is not set. COEP (require-corp) prevents the page from loading cross-origin resources unless they explicitly opt in. It is required alongside COOP to achieve cross-origin isolation. Absence is informational for most sites — only needed if your app uses SharedArrayBuffer or high-resolution performance timers.",
      evidence: `GET ${finalUrl}\nCross-Origin-Embedder-Policy: (header absent from response)`,
      solution: "Add: Cross-Origin-Embedder-Policy: require-corp. Note: this requires all subresources to serve a CORP or CORS header. Use credentialless if require-corp causes third-party resource breakage.",
      cweId: "CWE-346",
      wstgId: "WSTG-CONF-07",
    }));
  }

  const corp = headerVal(rawHeaders, "cross-origin-resource-policy");
  if (!corp) {
    vulnerabilities.push(vuln({
      name: "Missing Cross-Origin-Resource-Policy (CORP)",
      severity: "info",
      category: "Browser Feature Control",
      description: "The Cross-Origin-Resource-Policy header is absent. Without CORP, other origins can include this resource in their pages (via <img>, <script>, etc.). In cross-origin isolated contexts this could expose content to Spectre-class timing attacks. For most public resources this is informational — but adding CORP: same-origin or same-site is a low-effort hardening step.",
      evidence: `GET ${finalUrl}\nCross-Origin-Resource-Policy: (header absent from response)`,
      solution: "Add: Cross-Origin-Resource-Policy: same-origin (for same-site-only resources) or same-site. Use cross-origin only for truly public resources.",
      cweId: "CWE-346",
      wstgId: "WSTG-CONF-07",
    }));
  }

  // ── CORS ───────────────────────────────────────────────────────────────
  const acao = headerVal(rawHeaders, "access-control-allow-origin");
  if (acao === "*") {
    vulnerabilities.push(vuln({
      name: "Permissive CORS Policy (Wildcard Origin)",
      severity: "medium",
      category: "CORS Misconfiguration",
      description: "The server responds with Access-Control-Allow-Origin: *, meaning any website can make cross-origin requests to this endpoint and read the response. If this endpoint returns sensitive data, that data is exposed to all origins.",
      evidence: `GET ${finalUrl}\nAccess-Control-Allow-Origin: *`,
      solution: "Replace the wildcard with a specific allowlist of trusted origins: Access-Control-Allow-Origin: https://your-frontend.com. Never use * on endpoints that return user-specific data.",
      cweId: "CWE-942",
      cvssScore: 6.5,
      wstgId: "WSTG-CONF-07",
    }));
  }

  // ── Server / Technology Disclosure ────────────────────────────────────
  if (server && /\d/.test(server)) {
    vulnerabilities.push(vuln({
      name: "Server Version Disclosure",
      severity: "info",
      category: "Information Disclosure",
      description: `The Server header reveals detailed software version information: "${server}". Attackers use this to look up CVEs for the exact version and craft targeted exploits.`,
      evidence: `GET ${finalUrl}\nServer: ${server}`,
      solution: "Configure your web server to omit version numbers from the Server header, or remove the header entirely. In Nginx: server_tokens off; In Apache: ServerTokens Prod; ServerSignature Off",
      cweId: "CWE-200",
      wstgId: "WSTG-INFO-02",
    }));
  }

  const poweredBy = headerVal(rawHeaders, "x-powered-by");
  if (poweredBy) {
    vulnerabilities.push(vuln({
      name: "X-Powered-By Header Discloses Technology Stack",
      severity: "info",
      category: "Information Disclosure",
      description: `The X-Powered-By header advertises the underlying technology: "${poweredBy}". This helps attackers fingerprint your stack and search for known vulnerabilities.`,
      evidence: `GET ${finalUrl}\nX-Powered-By: ${poweredBy}`,
      solution: "Remove the X-Powered-By header. In Express.js: app.disable('x-powered-by'); In PHP: expose_php = Off in php.ini",
      cweId: "CWE-200",
      wstgId: "WSTG-INFO-09",
    }));
  }

  // ── Cookie analysis ───────────────────────────────────────────────────
  const setCookie = headerVal(rawHeaders, "set-cookie");
  vulnerabilities.push(...analyzeCookies(initial.setCookies ?? [], setCookie));

  // ── Mixed content ─────────────────────────────────────────────────────
  if (isHttps && /src=["']http:\/\//i.test(html.slice(0, 100_000))) {
    vulnerabilities.push(vuln({
      name: "Mixed Content (HTTP Resources on HTTPS Page)",
      severity: "medium",
      category: "Transport Security",
      description: "The HTTPS page loads resources (scripts, stylesheets, images) over plain HTTP. Browsers block or warn about mixed content, and the HTTP resources can be intercepted and modified by attackers.",
      evidence: `GET ${finalUrl}\nPage is served over HTTPS but contains src="http://..." resource references`,
      solution: "Update all resource URLs to use HTTPS. Use protocol-relative URLs (//example.com/resource) or absolute HTTPS URLs. Enable Content-Security-Policy: upgrade-insecure-requests",
      cweId: "CWE-311",
      cvssScore: 5.9,
      wstgId: "WSTG-CRYP-01",
    }));
  }

  // X-XSS-Protection: 0 is intentionally NOT flagged.
  // Disabling the browser's legacy XSS auditor is the current OWASP/Google/Mozilla
  // recommendation — the auditor was deprecated, causes false positives, and has
  // introduced its own XSS vulnerabilities in some browsers. Setting it to 0 is correct.

  // ── Cache-Control on sensitive-looking pages ───────────────────────────
  const cacheControl = headerVal(rawHeaders, "cache-control");
  const pragma = headerVal(rawHeaders, "pragma");
  if (isHttps && !cacheControl && !pragma) {
    vulnerabilities.push(vuln({
      name: "Missing Cache-Control Headers",
      severity: "info",
      category: "Information Disclosure",
      description: "No Cache-Control or Pragma headers are set. Without explicit cache directives, proxies and shared caches may store sensitive page content, potentially serving it to other users or making it accessible after logout.",
      evidence: `GET ${finalUrl}\nCache-Control: (header absent)\nPragma: (header absent)`,
      solution: "Set Cache-Control: no-store, no-cache, must-revalidate on pages with sensitive or personalized content. Use Cache-Control: public, max-age=3600 only for truly static, non-sensitive resources.",
      cweId: "CWE-524",
      wstgId: "WSTG-CONF-07",
    }));
  }

  // Pages the crawler will visit. Was 20 for deep scans and 0 (no crawl) for
  // basic ones; with one tier there is one budget.
  const CRAWL_PAGE_BUDGET = 20;

  // Did the edge answer instead of the site? Decided once, up front, because
  // several checks downstream are only meaningful if the document is the
  // target's own.
  const challengeVerdict = detectChallengePage(initial.status, html, rawHeaders);

  // ── Run all parallel probes ───────────────────────────────────────────
  // All checks run concurrently — active HTTP probes, DNS checks, site crawl,
  // CVE lookup, JWT analysis, subdomain takeover, JS secret scanning and path
  // traversal.
  // Every test's outcome — ran, skipped (and why) or failed — for the per-test
  // log the worker writes and the coverage line in the report. See testLedger.ts.
  const ledger = new TestLedger(onTest);
  // The header, cookie and CSP checks above ran on the first response before the
  // ledger existed. Record them now, so they are counted like every other test, and
  // never as run when a bot-protection page answered instead of the site (their
  // findings are withheld below, so nothing was actually checked).
  ledger.records.push(
    challengeVerdict.isChallenge
      ? { group: "passive", name: "response headers and cookies", status: "skipped", findings: 0, durationMs: 0, reason: "a bot-protection page answered instead of the site" }
      : { group: "passive", name: "response headers and cookies", status: "ran", findings: vulnerabilities.filter((v) => v.category !== "Scan Coverage").length, durationMs: 0 },
  );
  const crawlStarted = Date.now();

  // Run crawl separately to capture pagesVisited alongside findings
  const crawlPromise = crawlAndCheck(
    finalUrl, html, rawHeaders, initial.setCookies ?? [], CRAWL_PAGE_BUDGET,
  )
    .then((r) => {
      ledger.records.push({
        group: "crawl", name: `site crawl (${r.pagesVisited.length} inner pages)`, status: "ran",
        findings: r.vulnerabilities.length, durationMs: Date.now() - crawlStarted,
      });
      return { ...r, failed: false };
    })
    .catch((err: unknown) => {
      ledger.records.push({
        group: "crawl", name: "site crawl", status: "failed", findings: 0, durationMs: Date.now() - crawlStarted,
        reason: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200),
      });
      // Same reasoning as the probe families below: a crawl that died is not a
      // site without inner pages, and the report has to be able to tell them
      // apart.
      console.error("[scan] site crawl failed", err);
      return { vulnerabilities: [], pagesVisited: [], probedNotFound: [], failed: true };
    });

  // Each family is named, and its failure is NOT swallowed here.
  //
  // Every entry used to carry its own `.catch(() => [])`, which meant
  // Promise.allSettled never saw a rejection: a probe family that crashed
  // returned an empty array and was indistinguishable, in the report and in the
  // grade, from one that ran and found nothing. Seventeen families, seventeen
  // ways for a scan to look clean because it broke.
  //
  // Failures are collected and reported once, below, as a Scan Coverage finding.
  // That is deliberately not a vulnerability finding: a probe that could not run
  // is not evidence of a weakness, and inventing one would be the false positive
  // this exists to avoid. It says only "this was not checked", which is the one
  // thing the old behaviour could never say.
  // runAllProbes bundles thirteen checks behind one promise and filters its own
  // rejections, so a single failed check inside it would not surface as a
  // failure of the family. It reports them individually through this callback.
  const innerProbeFailures: string[] = [];

  const namedProbes: Array<{ family: string; run: Promise<ScanVulnerability[]> }> = [
    {
      family: "HTTP probes (headers, files, methods, CORS)",
      run: runAllProbes(finalUrl, html, allowActiveProbes, (checkName, reason) => {
        innerProbeFailures.push(checkName);
        console.error(`[scan] check failed: ${checkName}`, reason);
      }, ledger),
    },
    { family: "DNS and email authentication", run: checkDnsSecurity(finalUrl) },
    // Mail transport security: does the domain's MX actually offer STARTTLS,
    // and is its certificate valid. Invisible from the web tier — a site can
    // score perfectly on HTTPS while password-reset mail is relayed in
    // cleartext. SPF/DMARC say who MAY send; they say nothing about encryption.
    {
      family: "mail transport security (STARTTLS, MX certificate)",
      run: (async () => {
        const { hostname } = new URL(finalUrl);
        const { inspectMailTls, mailTlsFindings } = await import("./mailTls.js");
        return mailTlsFindings(await inspectMailTls(hostname));
      })(),
    },
    // Structured data, social preview metadata and indexability. No network
    // calls — it reads the document already fetched. Presentation findings are
    // INFO (weight 0) so they cannot move the security grade; only genuine
    // exposure (internal hosts, http assets, foreign canonical) carries weight.
    {
      family: "structured data and social metadata",
      run: (async () => {
        const { structuredDataFindings } = await import("./structuredData.js");
        return structuredDataFindings(finalUrl, html, { status: initial.status, headers: rawHeaders });
      })(),
    },
    { family: "known-CVE and end-of-life versions", run: checkForKnownVulnerabilities(html, rawHeaders) },
    // Passive JWT analysis — no extra HTTP requests
    { family: "JWT analysis", run: analyzeJwts(rawHeaders, html) },
    // Subdomain takeover — 1-2 DNS + HTTP checks
    { family: "subdomain takeover", run: checkSubdomainTakeover(finalUrl) },
    // Source map exposure — checks JS bundles for .map files
    { family: "source map exposure", run: checkSourceMaps(html, finalUrl) },
    // Exposed API docs: Swagger/OpenAPI/ReDoc — fetching published doc paths
    { family: "exposed API documentation", run: runApiDocsProbe(finalUrl) },
    { family: "health endpoint disclosure", run: runHealthEndpointProbe(finalUrl) },
    // Next.js __NEXT_DATA__ prop leaks — read from the page already fetched
    { family: "Next.js __NEXT_DATA__ secrets", run: runNextjsProbe(finalUrl, html) },
  ];

  // Everything below reads data out of a backend the target owns, or fuzzes an
  // endpoint to see what it admits to. That is testing, not visiting.
  const activeFamilies = [
    "Supabase RLS and Firebase rules",
    "BaaS open data (PocketBase, Appwrite)",
    "GraphQL introspection",
    "public cloud storage buckets",
    "dependency CVEs from an exposed manifest",
    "path traversal",
    "injection (XSS, SQLi)",
  ];
  if (!allowActiveProbes) {
    for (const family of activeFamilies) ledger.skip("active", family, NOT_VERIFIED);
  }
  if (allowActiveProbes) {
    namedProbes.push(
      // Vibe-stack database security — Supabase RLS + Firebase rules (both tiers)
      { family: "Supabase RLS and Firebase rules", run: checkVibeStackSecurity(html, finalUrl, tier) },
      // BaaS open-data checks not covered above: PocketBase, Appwrite
      { family: "BaaS open data (PocketBase, Appwrite)", run: runBaasProbes(finalUrl, html) },
      // GraphQL introspection + field suggestions
      { family: "GraphQL introspection", run: runGraphqlProbe(finalUrl, html) },
      // Public cloud storage listing: S3, GCS, Azure Blob
      { family: "public cloud storage buckets", run: runStorageProbe(finalUrl, html) },
      // Real SCA, when the target publishes its own manifest. The path probe
      // already reports that /package.json is exposed; this reads the
      // dependency tree inside it and matches it against OSV, which is the
      // thing that finding tells the customer an attacker would do.
      {
        family: "dependency CVEs from an exposed manifest",
        run: (async () => {
          const { scaFromExposedManifest } = await import("./manifestSca.js");
          return scaFromExposedManifest(new URL(finalUrl).origin);
        })(),
      },
    );
  }

  namedProbes.push({ family: "JavaScript secret scanning", run: scanJavaScriptForSecrets(html, finalUrl) });

  // Optional source-code scan of a public GitHub repository the user
  // supplied for this scan — see githubSourceProbe.ts. Independent of
  // allowActiveProbes: this never sends a request to the scan target at all,
  // only to GitHub's own public API, so it carries none of the risk that
  // gate exists to control.
  if (extra?.githubRepoUrl) {
    const repoRef = parseGithubRepoRef(extra.githubRepoUrl);
    if (repoRef) {
      namedProbes.push({
        family: "GitHub source code secrets",
        // A repository that could not be read throws, so the ledger records it as failed and
        // the coverage note names it, instead of it reading as a clean "nothing found".
        run: scanGithubRepo(repoRef).then((outcome) => {
          const why = githubNotScannedReason(outcome.status);
          if (why) throw new Error(why);
          return outcome.findings;
        }),
      });
    } else {
      ledger.skip("passive", "GitHub source code secrets", "the supplied value was not a recognisable GitHub repository");
    }
  } else {
    ledger.skip("passive", "GitHub source code secrets", "no repository was supplied for this scan");
  }

  if (allowActiveProbes) {
    namedProbes.push(
      // Active path traversal probing — multiple HTTP requests
      { family: "path traversal", run: checkPathTraversal(finalUrl, html) },
      // A03 Injection — reflected XSS + error-based SQLi active probing
      { family: "injection (XSS, SQLi)", run: runInjectionProbes(finalUrl, html) },
    );
  }

  const [crawlResult, ...probeResults] = await Promise.all([
    crawlPromise,
    Promise.allSettled(
      namedProbes.map((p) =>
        // The HTTP probes bundle records its thirteen checks one by one inside
        // runAllProbes; recording the bundle too would count them twice.
        p.family.startsWith("HTTP probes")
          ? p.run
          : ledger.track(activeFamilies.includes(p.family) ? "active" : "passive", p.family, p.run),
      ),
    ),
  ]);

  vulnerabilities.push(...crawlResult.vulnerabilities);

  // Families that threw rather than answering. Named, so the coverage note
  // below can say which — "something failed" is not useful to anyone.
  const unrunFamilies: string[] = [];
  const settledProbes = probeResults[0] as PromiseSettledResult<ScanVulnerability[]>[];
  settledProbes.forEach((result, i) => {
    if (result.status === "fulfilled") {
      vulnerabilities.push(...result.value);
      return;
    }
    const family = namedProbes[i]?.family ?? `probe #${i}`;
    unrunFamilies.push(family);
    console.error(`[scan] probe family failed: ${family}`, result.reason);
  });

  if (crawlResult.failed) unrunFamilies.push("site crawl (inner pages)");
  // Individual checks from inside runAllProbes, already logged as they failed.
  unrunFamilies.push(...innerProbeFailures);

  // ── API surface testing ────────────────────────────────────────────────────
  // Discovery reads the JS bundles, and the probes spend a few requests per
  // endpoint. On an API-first SPA this is the only path that finds anything at
  // all — the HTML carries no forms, links or parameters to collect.
  //
  // Each stage used to swallow its own failure with `.catch(() => [])`, the
  // same defect the coverage note above exists to catch on the passive probes
  // — a thrown error and a clean "nothing found" produced byte-identical
  // output. SSRF is the one that matters most here: its whole method is a
  // negative result ("no callback arrived"), so a failed OOB registration or a
  // network fault looked exactly like a target that is not vulnerable.
  if (!allowActiveProbes) {
    ledger.skip("active", "API surface discovery", NOT_VERIFIED);
    ledger.skip("active", "API endpoint testing (auth, injection, IDOR, mass assignment)", NOT_VERIFIED);
    ledger.skip("active", "SSRF (out-of-band callback)", NOT_VERIFIED);
    ledger.skip("active", "LLM prompt injection (system prompt extraction)", NOT_VERIFIED);
    ledger.skip("active", "race condition (one-time action)", NOT_VERIFIED);
  }
  if (allowActiveProbes) {
    const origin = new URL(finalUrl).origin;
    const discoveryStarted = Date.now();
    const endpoints = await collectApiSurface(origin, html, observedRequests)
      .then((found) => {
        ledger.records.push({
          group: "active", name: `API surface discovery (${found.length} endpoints)`, status: "ran",
          findings: 0, durationMs: Date.now() - discoveryStarted,
        });
        return found;
      })
      .catch((err: unknown) => {
        ledger.records.push({
          group: "active", name: "API surface discovery", status: "failed", findings: 0,
          durationMs: Date.now() - discoveryStarted,
          reason: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200),
        });
        unrunFamilies.push("API surface discovery");
        console.error("[scan] API surface discovery failed", err);
        return [] as ApiEndpoint[];
      });
    if (endpoints.length === 0) {
      ledger.skip("active", "API endpoint testing (auth, injection, IDOR, mass assignment)", "no API endpoints were found to test");
    }

    const apiFindings = await (async () => {
      if (endpoints.length === 0) return [] as ScanVulnerability[];
      return ledger.track("active", "API endpoint testing (auth, injection, IDOR, mass assignment)", runApiProbes({
        endpoints,
        ...(auth?.credentials ? { credentials: auth.credentials } : {}),
        ...(auth?.secondary ? { secondary: auth.secondary } : {}),
      }));
    })().catch((err: unknown) => {
      unrunFamilies.push("API endpoint testing (auth, injection, IDOR, mass assignment)");
      console.error("[scan] API probes failed", err);
      return [] as ScanVulnerability[];
    });
    vulnerabilities.push(...apiFindings);

    // ── LLM prompt injection (system prompt extraction) ──────────────────────
    // Only meaningful when the passive AI-feature check already found the
    // target's system prompt sitting in its own client-side JS — that known
    // text is what makes this a stable check rather than a judged one. See
    // promptInjectionProbe.ts.
    const knownSystemPrompt = extractSystemPromptText(await collectJavaScript(html, finalUrl));
    if (!knownSystemPrompt) {
      ledger.skip(
        "active",
        "LLM prompt injection (system prompt extraction)",
        "no system prompt was found in this site's client-side code to check against",
      );
    } else {
      const injectionFindings = await ledger
        .track(
          "active",
          "LLM prompt injection (system prompt extraction)",
          runPromptInjectionProbe({
            knownSystemPrompt,
            endpoints: endpoints.map((e) => e.url),
            ...(auth?.credentials ? { credentials: auth.credentials } : {}),
          }),
        )
        .catch((err: unknown) => {
          unrunFamilies.push("LLM prompt injection (system prompt extraction)");
          console.error("[scan] prompt injection probe failed", err);
          return [] as ScanVulnerability[];
        });
      vulnerabilities.push(...injectionFindings);
    }

    // ── Race condition (one-time action) ──────────────────────────────────────
    // Explicit per-scan opt-in only — see raceConditionProbe.ts for why this is
    // gated separately from every other active check.
    if (extra?.raceConditionTesting) {
      if (!auth?.credentials) {
        ledger.skip("active", "race condition (one-time action)", "needs a signed-in test account to run against");
      } else {
        const raceFindings = await ledger
          .track(
            "active",
            "race condition (one-time action)",
            runRaceConditionProbe({ endpoints: endpoints.map((e) => e.url), credentials: auth.credentials }),
          )
          .catch((err: unknown) => {
            unrunFamilies.push("race condition (one-time action)");
            console.error("[scan] race condition probe failed", err);
            return [] as ScanVulnerability[];
          });
        vulnerabilities.push(...raceFindings);
      }
    } else {
      // Logged so every scan shows this test and why it did not run, rather than leaving no trace.
      ledger.skip("active", "race condition (one-time action)", "not requested for this scan (opt-in only, because it acts on the test account)");
    }

    // ── A10: SSRF via the out-of-band collector ─────────────────────────────
    // Runs only when a public callback host is configured, since the target's
    // server is what has to reach it. Reuses the discovered endpoints.
    // runSsrfProbes returns nothing when no callback host is configured —
    // recorded as a skip, so it cannot read as "not vulnerable".
    let ssrfRun: Promise<ScanVulnerability[]>;
    if (isOobConfigured()) {
      ssrfRun = ledger.track("active", "SSRF (out-of-band callback)", runSsrfProbes({
        scanId,
        targetUrl: finalUrl,
        endpoints,
        ...(auth?.credentials ? { credentials: auth.credentials } : {}),
      }));
    } else {
      ledger.skip("active", "SSRF (out-of-band callback)", "no public callback host is configured (OOB_BASE_URL / APP_ORIGIN)");
      ssrfRun = Promise.resolve([]);
    }
    const ssrfFindings = await ssrfRun.catch((err: unknown) => {
      unrunFamilies.push("SSRF (out-of-band callback)");
      console.error("[scan] SSRF probe failed", err);
      return [] as ScanVulnerability[];
    });
    vulnerabilities.push(...ssrfFindings);
  }

  // ── A01: broken access control ─────────────────────────────────────────────
  // Runs last because it needs the crawl's output: the URLs the signed-in
  // account actually reached are the ones worth asking a second account for.
  // Requires both accounts — one identity cannot demonstrate an authorisation
  // boundary between users.
  //
  // When a primary account is signed in but no second one was supplied, try
  // once to create a disposable one through the target's own public signup
  // form (see autoSecondAccount.ts) before falling back to skipping this
  // check. This never runs against a target with no logged-in primary
  // account at all — there would be nothing to compare a second identity to.
  let effectiveSecondary = auth?.secondary;
  let autoSecondAccountSkipReason: string | null = null;
  if (allowActiveProbes && auth?.credentials && !effectiveSecondary) {
    const attempt = await attemptAutoSecondAccount(finalUrl).catch((err: unknown) => {
      console.error("[scan] auto second-account creation failed", err);
      return { secondary: null, skippedReason: "attempting an automatic second account failed" } as const;
    });
    if (attempt.secondary) {
      effectiveSecondary = attempt.secondary;
    } else {
      autoSecondAccountSkipReason = attempt.skippedReason ?? "no second account available";
    }
  }

  if (!allowActiveProbes) {
    ledger.skip("active", "cross-account access control (IDOR)", NOT_VERIFIED);
  } else if (!effectiveSecondary) {
    ledger.skip(
      "active",
      "cross-account access control (IDOR)",
      autoSecondAccountSkipReason
        ? `no second test account was supplied, and an automatic attempt to create one did not succeed: ${autoSecondAccountSkipReason}`
        : "needs sign-ins for two test accounts on the scan",
    );
  }
  if (allowActiveProbes && auth?.credentials && effectiveSecondary) {
    const candidateUrls = [finalUrl, ...crawlResult.pagesVisited];
    const accessFindings = await ledger.track("active", "cross-account access control (IDOR)", runAccessControlProbes({
      urls: candidateUrls,
      primary: auth.credentials,
      secondary: effectiveSecondary,
    })).catch((err: unknown) => {
      unrunFamilies.push("cross-account access control (IDOR)");
      console.error("[scan] access control probes failed", err);
      return [] as ScanVulnerability[];
    });
    vulnerabilities.push(...accessFindings);
  }

  if (unrunFamilies.length > 0) {
    vulnerabilities.push(vuln({
      name: `${unrunFamilies.length} check group${unrunFamilies.length > 1 ? "s" : ""} could not be completed`,
      severity: "info",
      category: "Scan Coverage",
      description:
        `${unrunFamilies.length} group${unrunFamilies.length > 1 ? "s" : ""} of checks failed to run on this scan — a network error, a timeout, or an internal fault. ` +
        `This is not a finding about your site, and it does not mean anything is wrong with it. It is here because the alternative is worse: ` +
        `a check group that dies silently returns nothing, which looks exactly like a check group that ran and found nothing. ` +
        `Anything those groups would have caught is simply unknown for this scan, so re-run it before treating a clean result in these areas as meaningful.`,
      evidence: `Not completed:\n${unrunFamilies.map((f) => `  • ${f}`).join("\n")}`,
      solution:
        "Re-run the scan. If the same group fails repeatedly, the target may be rate-limiting or blocking the scanner, or the check has a genuine fault worth reporting to us.",
      confidence: 100,
    }));
  }

  // Two rate-limit checks can fire on one scan: a header heuristic in
  // probes.ts, and the behavioural burst in apiProbe.ts. When both appear they
  // describe the same problem, and the behavioural one has actually
  // demonstrated it — the header check itself says infrastructure often
  // throttles without advertising it. Keep the evidence, drop the inference.
  const hasBehaviouralRateLimitFinding = vulnerabilities.some(
    (v) => v.name === "API Endpoints Without Rate Limiting",
  );
  const rateLimitDeduped = hasBehaviouralRateLimitFinding
    ? vulnerabilities.filter((v) => v.name !== "Rate Limiting Not Advertised in Response Headers")
    : vulnerabilities;

  // When an edge answered instead of the origin, every check that read the
  // response body or its headers describes the challenge page. Naming those
  // findings as untrusted in a Scan Coverage note was not enough: the report
  // still said "etsy.com is missing Content-Security-Policy and serves a
  // wildcard CORS policy", which is a statement about Cloudflare's
  // interstitial and false about Etsy. Twelve of eighteen findings on that
  // scan came from a page Etsy did not serve.
  //
  // This is an allowlist rather than a denylist on purpose. The question is
  // not "which findings look content-derived" but "which sources did not read
  // the intercepted response at all" — DNS, mail transport and the scan's own
  // coverage notes. Anything else is dropped, because over-suppressing behind
  // an aggressive WAF costs a finding, while under-suppressing attributes
  // another company's error page to the customer.
  const deduped = withholdInterceptedFindings(rateLimitDeduped, challengeVerdict.isChallenge);

  return {
    targetUrl,
    finalUrl,
    statusCode: initial.status,
    server,
    tlsGrade,
    technologies,
    vulnerabilities: autoEnrichConfidence(
      [
        ...deduped,
        ...(sessionWasLost() ? [sessionLostFinding()] : []),
        ...(allowActiveProbes ? [] : [activeProbesSkippedFinding()]),
        ...(challengeVerdict.isChallenge
          ? [interceptedFinding(challengeVerdict.vendor, challengeVerdict.signal ?? "")]
          : []),
      ],
      technologies,
    ),
    requestDurationMs,
    rawHeaders,
    pagesScanned: crawlResult.pagesVisited,
    probedNotFound: crawlResult.probedNotFound,
    renderedWithBrowser,
    intercepted: challengeVerdict.isChallenge,
    tests: ledger.records,
  };
}

export function computeRiskScore(vulns: ScanVulnerability[]): number {
  let score = 0;
  for (const v of vulns) {
    switch (v.severity) {
      case "critical": score += 30; break;
      case "high":     score += 15; break;
      case "medium":   score += 5;  break;
      case "low":      score += 1;  break;
      case "info":     score += 0;  break;
    }
  }
  return Math.min(score, 100);
}

export function computeGrade(riskScore: number): string {
  if (riskScore <= 10) return "A";
  if (riskScore <= 25) return "B";
  if (riskScore <= 45) return "C";
  if (riskScore <= 65) return "D";
  return "F";
}

/**
 * The grade sentinel for a scan that must not be graded at all.
 *
 * A bot-protection layer that answers instead of the origin drives
 * computeRiskScore to 0 — the best score — because every finding that could
 * deduct was withheld, not because the site is clean. Grading it A is the exact
 * inversion the false-positive audit kept catching: an interstitial's silence
 * read as the target's merit. The report and dashboard render this value as
 * "coverage incomplete".
 */
export const GRADE_INCOMPLETE = "N/A";

/** computeGrade, except an intercepted scan yields the incomplete sentinel. */
export function gradeForResult(riskScore: number, intercepted: boolean): string {
  return intercepted ? GRADE_INCOMPLETE : computeGrade(riskScore);
}

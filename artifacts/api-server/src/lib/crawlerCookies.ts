/** Cookie checks on crawled pages. */
import { isLikelySessionCookie, requiresHttpOnly } from "./cookieClassification.js";
import { parseSetCookie } from "./cookieFlags.js";
import { detectSerializedCookies } from "./deserializationProbe.js";
import type { ScanVulnerability } from "./scanner";
import { vuln } from "./crawlerFetch";

/**
 * A Set-Cookie line safe to put in a report: the value replaced, every
 * attribute kept.
 *
 * Cookie findings are derived entirely from the name and the flags, so the value
 * is the one part that carries no diagnostic weight and all of the risk. It was
 * being quoted in full, which matters because report evidence is durable and
 * shareable: it is stored in the reports table, rendered into the emailed PDF,
 * and readable by anyone holding a share link, which the privacy page tells
 * people to treat as public. On a CREDENTIALED scan the scanner is signed in, so
 * the value being quoted is a live authenticated session token.
 *
 * scanner.ts already reports root-page cookie findings by name alone, and
 * deserializationProbe.ts redacts explicitly; this brings the inner-page path in
 * line with both.
 */
export function redactCookieValue(setCookie: string): string {
  const line = setCookie.trim();
  const eq = line.indexOf("=");
  if (eq <= 0) return line;
  const semi = line.indexOf(";");
  const valueEnd = semi === -1 ? line.length : semi;
  if (valueEnd <= eq) return line;
  return `${line.slice(0, eq)}=<redacted>${line.slice(valueEnd)}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// PER-PAGE COOKIE CHECKS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check cookie security flags on a single inner page's Set-Cookie headers.
 *
 * @param seenCookieIssues - shared Set across the whole crawl; each entry is
 *   "issueName::cookieName". Prevents the same cookie problem from being filed
 *   once per crawled page (e.g. Replit's GAESA cookie on every response).
 */
// Cookies set by third-party infrastructure (CDN proxies, load balancers, etc.)
// that the site owner cannot control.  Must match the list in scanner.ts.
export const INFRA_COOKIE_NAMES = new Set([
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

export function checkPageCookies(
  setCookies: string[],
  pageUrl: string,
  isHttps: boolean,
  seenCookieIssues: Set<string>,
  discoveredBy: "crawl" | "probe",
): ScanVulnerability[] {
  if (setCookies.length === 0) return [];
  const path = (() => { try { return new URL(pageUrl).pathname; } catch { return pageUrl; } })();
  const findings: ScanVulnerability[] = [];

  // Insecure deserialization: a native serialized object stored in a cookie the
  // server issues is deserialized on every request (CWE-502). Passive — reads
  // the same Set-Cookie headers the flag checks below already have. Deduped via
  // the shared seenCookieIssues set. See lib/deserializationProbe.ts.
  for (const partial of detectSerializedCookies(setCookies, pageUrl, seenCookieIssues)) {
    findings.push(vuln(partial));
  }
  // Prefix added to evidence lines so the report UI can distinguish how the page was found
  const sourcePrefix = discoveredBy === "probe" ? "[Direct probe] " : "";

  for (const cookie of setCookies) {
    if (!cookie.trim()) continue;
    // Skip malformed Set-Cookie fragments that have no name=value pair.
    // These arise from dates in expires= values that get mis-split upstream.
    // Flags are read from the attributes (parseSetCookie), exactly as the root scan does: a
    // regex over the whole line also matched a cookie NAME or value containing "secure".
    const parsed = parseSetCookie(cookie);
    if (!parsed) continue;
    // A cookie the server is clearing (Max-Age=0 / past Expires) carries no session.
    if (parsed.deleted) continue;
    const namePart = parsed.name;

    // Skip infrastructure-owned cookies that the site operator cannot modify.
    if (INFRA_COOKIE_NAMES.has(namePart.toLowerCase())) continue;

    // Non-session cookies (UI-state flags, analytics/tracking IDs) pose much
    // less real risk than an actual session/auth cookie missing these flags —
    // see isLikelySessionCookie in scanner.ts for the shared classification.
    const isSession = isLikelySessionCookie(namePart);

    if (isHttps && !parsed.secure) {
      const key = `secure::${namePart}`;
      if (!seenCookieIssues.has(key)) {
        seenCookieIssues.add(key);
        findings.push(vuln({
          name: isSession ? "Session Cookie Missing Secure Flag on Inner Page" : "Non-Session Cookie Missing Secure Flag on Inner Page",
          severity: isSession ? "high" : "low",
          category: "Session Management",
          description: isSession
            ? `The page "${path}" sets the cookie "${namePart}" without the Secure flag, allowing it to be transmitted over unencrypted HTTP even on an HTTPS site.`
            : `The page "${path}" sets the cookie "${namePart}" without the Secure flag. It doesn't appear to carry session/auth state, so the practical risk is low.`,
          evidence: `${sourcePrefix}GET ${pageUrl}\nSet-Cookie: ${redactCookieValue(cookie)}`,
          solution: "Add the Secure attribute to all cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
          cweId: "CWE-614",
          cvssScore: isSession ? 6.5 : 3.1,
          wstgId: "WSTG-SESS-02",
          ...(isSession ? {} : { confidence: 70 }),
        }));
      }
    }

    // A double-submit CSRF token has to stay readable by JavaScript; see
    // requiresHttpOnly. The root scan applies the same exemption.
    if (!parsed.httpOnly && requiresHttpOnly(namePart)) {
      const key = `httponly::${namePart}`;
      if (!seenCookieIssues.has(key)) {
        seenCookieIssues.add(key);
        findings.push(vuln({
          name: isSession ? "Session Cookie Missing HttpOnly Flag on Inner Page" : "Non-Session Cookie Readable by JavaScript on Inner Page",
          severity: isSession ? "medium" : "info",
          category: "Session Management",
          description: isSession
            ? `The page "${path}" sets the cookie "${namePart}" without the HttpOnly flag, allowing client-side JavaScript to access it. This enables session theft via XSS.`
            : `The page "${path}" sets the cookie "${namePart}" without the HttpOnly flag. It doesn't appear to carry session/auth state — many such cookies (UI-state flags, analytics IDs) are intentionally client-readable.`,
          evidence: `${sourcePrefix}GET ${pageUrl}\nSet-Cookie: ${redactCookieValue(cookie)}`,
          solution: "Add the HttpOnly attribute to all session cookies: Set-Cookie: name=value; HttpOnly; Secure; SameSite=Lax",
          cweId: "CWE-1004",
          cvssScore: isSession ? 5.3 : 2.6,
          wstgId: "WSTG-SESS-02",
          ...(isSession ? {} : { confidence: 60 }),
        }));
      }
    }
  }

  return findings;
}

/**
 * The cookie defects the ROOT response already reported, as dedup keys.
 *
 * The crawl's dedup set must start from these rather than empty. The root page's
 * cookies are analysed separately in scanner.ts, so a cookie set on BOTH the root
 * and an inner page was reported twice: once as "Missing Secure Flag" and again
 * as "Missing Secure Flag on Inner Page". Same cookie, same defect, two findings.
 *
 * Seen on google.com: NID is set on / and on /imghp and came back as two
 * findings. Both were factually correct, which is what makes this kind of
 * duplication corrosive — the user checks, finds the scanner is right, and still
 * counts the second one as noise.
 *
 * Only records what the root WOULD have reported, so a defect the root did not
 * flag is still catchable on an inner page. Uses the same split and key format as
 * scanner.ts; a different split would seed the wrong names and either duplicate
 * anyway or suppress a genuine finding.
 */
export function seedCookieIssuesFromRoot(rootSetCookies: string[]): Set<string> {
  const seen = new Set<string>();
  for (const cookie of rootSetCookies) {
    const parsed = parseSetCookie(cookie);
    // A cookie the root is clearing is skipped there, so it must not seed a key here.
    if (!parsed || parsed.deleted) continue;
    const namePart = parsed.name === "cookie" ? "" : parsed.name;
    if (!namePart || INFRA_COOKIE_NAMES.has(namePart.toLowerCase())) continue;
    if (!parsed.secure) seen.add(`secure::${namePart}`);
    if (!parsed.httpOnly) seen.add(`httponly::${namePart}`);
  }
  return seen;
}

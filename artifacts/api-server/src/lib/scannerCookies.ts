import { parseSetCookie } from "./cookieFlags.js";
import { isLikelySessionCookie, requiresHttpOnly } from "./cookieClassification.js";
import { vuln, type ScanVulnerability } from "./scannerTypes";

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
export function analyzeCookies(setCookies: string[], flattenedFallback?: string): ScanVulnerability[] {
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
    const parsed = parseSetCookie(cookie);
    if (!parsed) continue;
    // A cookie the server is clearing (Max-Age=0 / past Expires) carries no session.
    if (parsed.deleted) continue;
    const namePart = parsed.name;

    // Skip cookies owned by third-party infrastructure — the site operator
    // cannot add Secure/HttpOnly/SameSite to cookies they don't set.
    if (INFRA_COOKIE_NAMES.has(namePart.toLowerCase())) continue;

    const isSession = isLikelySessionCookie(namePart);

    if (!parsed.secure)   (isSession ? noSecure : noSecureOther).push(namePart);
    // A CSRF token is exempt from HttpOnly and only from HttpOnly: the page has
    // to read it to echo it back. It still needs Secure and SameSite.
    if (!parsed.httpOnly && requiresHttpOnly(namePart)) {
      (isSession ? noHttpOnly : noHttpOnlyOther).push(namePart);
    }
    if (!parsed.sameSite) (isSession ? noSameSite : noSameSiteOther).push(namePart);
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
      // Low, not Medium: Chrome and Edge treat a cookie with no SameSite as Lax, which already
      // blocks it on cross-site POSTs, so the gap is Firefox and Safari plus any state-changing
      // GET. A missing attribute is not a CSRF; the active CSRF checks report the real thing.
      severity: "low",
      category: "CSRF Protection",
      description: `${noSameSite.length} likely session/auth cookie${plural ? "s lack" : " lacks"} the SameSite attribute (${list}). Chrome and Edge treat such a cookie as SameSite=Lax, which stops it being sent on cross-site form posts; Firefox and Safari do not, so in those browsers the application relies entirely on its own CSRF defences. This is a missing safety net, not a demonstrated CSRF.`,
      evidence: `Affected cookie${plural ? "s" : ""}: ${list}`,
      solution: "Set SameSite=Lax or SameSite=Strict on all session cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
      cweId: "CWE-352",
      cvssScore: 3.1,
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


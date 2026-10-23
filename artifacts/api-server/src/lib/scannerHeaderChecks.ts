import { cspRestrictsFraming, hasNosniff } from "./headerAnalysis.js";
import { checkIsolationHeaders } from "./isolationHeaders";
import { headerVal, vuln, type ScanVulnerability, type PageContext } from "./scannerTypes";

/**
 * Does a Server header name a software version ("nginx/1.31.3", "Apache/2.4.41", "Microsoft-IIS/10.0")?
 * A digit alone is not enough: www.php.net answers "BunnyCDN-HOU1-893", a CDN edge-node id that says nothing
 * about the software and gives an attacker no CVE to look up.
 */
export function carriesSoftwareVersion(server: string): boolean {
  return /\/\s*v?\d/i.test(server) || /\b\d+\.\d+/.test(server);
}

/** Framing, sniffing, referrer, permissions, cross-origin isolation, CORS and technology-disclosure headers. */
export function headerFindings({ finalUrl, rawHeaders }: PageContext): ScanVulnerability[] {
  const vulnerabilities: ScanVulnerability[] = [];

  // ── X-Frame-Options ───────────────────────────────────────────────────
  const csp = headerVal(rawHeaders, "content-security-policy");
  const server = headerVal(rawHeaders, "server") ?? null;
  const xfo = headerVal(rawHeaders, "x-frame-options");
  const cspFrameAncestors = cspRestrictsFraming(csp);
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
  if (!hasNosniff(xcto)) {
    vulnerabilities.push(vuln({
      name: "Missing X-Content-Type-Options: nosniff",
      severity: "medium",
      category: "Content Sniffing",
      description: "The X-Content-Type-Options header is absent or not set to 'nosniff'. Browsers may MIME-sniff response content and execute it as a different content type, enabling content-injection attacks.",
      evidence: xcto
        ? `GET ${finalUrl}\nX-Content-Type-Options: ${xcto}\n(must include "nosniff")`
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
      // Info: a hardening default, not an exposure. Browsers already send only the origin for most cross-site requests.
      severity: "info",
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
      // Info: it only limits browser features the page would have to ask the visitor for anyway.
      severity: "info",
      category: "Browser Feature Control",
      description: "No Permissions-Policy (formerly Feature-Policy) header is present. This header restricts which browser APIs (camera, microphone, geolocation, etc.) can be accessed from your pages and embedded iframes.",
      evidence: `GET ${finalUrl}\nPermissions-Policy: (header absent from response)`,
      solution: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=(). Adjust based on what your app actually needs.",
      cweId: "CWE-16",
      cvssScore: 2.4,
      wstgId: "WSTG-CONF-07",
    }));
  }

  // Cross-origin isolation headers (COOP / COEP / CORP) — isolationHeaders.ts.
  vulnerabilities.push(...checkIsolationHeaders(rawHeaders, finalUrl));

  // ── CORS ───────────────────────────────────────────────────────────────
  const acao = headerVal(rawHeaders, "access-control-allow-origin");
  if (acao === "*") {
    // GitHub Pages, Netlify and CDNs send this by default for public assets, and
    // browsers never attach cookies or credentials to a "*" response, so on its own
    // it exposes only what any visitor already sees. Credentials paired with "*"
    // is an invalid combination that signals a misconfigured intent, so keep LOW.
    const withCredentials = /^true$/i.test(headerVal(rawHeaders, "access-control-allow-credentials") ?? "");
    vulnerabilities.push(vuln({
      name: "Permissive CORS Policy (Wildcard Origin)",
      severity: withCredentials ? "low" : "info",
      category: "CORS Misconfiguration",
      description: withCredentials
        ? "The page responds with Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true. Browsers reject that combination, so credentialed cross-origin reads do not work, but it suggests the CORS configuration was not thought through."
        : "The page responds with Access-Control-Allow-Origin: *, so any website can read this response from a browser. That is normal for public, static content (hosting platforms and CDNs add it by default) and browsers do not send cookies with wildcard requests. It only matters if this or other endpoints return user-specific data without relying on cookies.",
      evidence: `GET ${finalUrl}\nAccess-Control-Allow-Origin: *${withCredentials ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
      solution: "If this site serves only public content, no action is needed. For endpoints that return user-specific data, replace the wildcard with an allowlist of trusted origins: Access-Control-Allow-Origin: https://your-frontend.com.",
      cweId: "CWE-942",
      wstgId: "WSTG-CONF-07",
    }));
  }

  // ── Server / Technology Disclosure ────────────────────────────────────
  if (server && carriesSoftwareVersion(server)) {
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

  return vulnerabilities;
}

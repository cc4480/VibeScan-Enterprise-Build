/** Probes of HTTP behaviour: methods, active CORS, clickjacking, open redirect. */
import type { ScanVulnerability } from "./scanner";
import { OPEN_REDIRECT_PROBE, OPEN_REDIRECT_PARAMS } from "./payloads";
import { safeGet, vuln } from "./probesCore";
import { cspRestrictsFraming } from "./headerAnalysis.js";

// ─────────────────────────────────────────────────────────────────────────────
// 2. HTTP METHODS PROBE
// ─────────────────────────────────────────────────────────────────────────────

export async function checkHttpMethods(targetUrl: string): Promise<ScanVulnerability[]> {
  const result = await safeGet(targetUrl, { method: "OPTIONS", redirect: "follow" });
  if (!result) return [];

  // Only read the standard HTTP Allow header — NOT Access-Control-Allow-Methods.
  // ACAM is a CORS preflight header that legitimately lists methods for cross-origin
  // requests; conflating it with Allow would flag all CORS-enabled API endpoints as
  // "dangerous methods" false positives.
  const allow = result.headers["allow"] ?? "";
  if (!allow) return [];

  const vulns: ScanVulnerability[] = [];

  if (/\bTRACE\b/i.test(allow)) {
    vulns.push(vuln({
      name: "HTTP TRACE Method Enabled (Cross-Site Tracing)",
      severity: "medium",
      category: "HTTP Security",
      description: "The HTTP TRACE method is enabled. It reflects the full request back to the client—including headers like Authorization and Cookie. Combined with XSS (Cross-Site Tracing / XST), an attacker can steal session tokens that are marked HttpOnly, bypassing that protection.",
      evidence: `OPTIONS ${targetUrl}\nAllow: ${allow}`,
      solution: "Disable TRACE server-wide. Apache: `TraceEnable Off`. Nginx: already off by default. IIS: Use URLScan or Request Filtering. This should be disabled regardless of whether XSS is present.",
      cweId: "CWE-16",
      cvssScore: 5.8,
      wstgId: "WSTG-CONF-06",
    }));
  }

  const dangerousMethods = ["PUT", "DELETE", "PATCH"].filter((m) =>
    new RegExp(`\\b${m}\\b`, "i").test(allow),
  );
  if (dangerousMethods.length > 0) {
    // MEDIUM, not HIGH, and named for what was observed rather than for a
    // conclusion. An Allow header says a method EXISTS at this path; it says
    // nothing about whether authorization guards it. Every REST API that
    // correctly implements PUT and DELETE behind auth advertises them here, and
    // at 7.5 this was handing those APIs a HIGH for being well-formed — the same
    // error FALSE-POSITIVE-AUDIT.md records against crossdomain.xml, the OpenAPI
    // spec check and the rate-limit check: reading the presence of a response as
    // the meaning of the response.
    //
    // Confirming it would mean sending an unauthenticated PUT or DELETE at a
    // stranger's server, which this scanner does not do (see destructive.ts), so
    // the honest report is the observation plus what the operator should check.
    vulns.push(vuln({
      name: `Write HTTP Methods Advertised (${dangerousMethods.join(", ")})`,
      severity: "medium",
      category: "HTTP Security",
      description: `The server advertises ${dangerousMethods.join("/")} in the Allow header for the root path. This scan did not attempt them, so it does not show whether they are reachable without authorization — on an API that guards writes, advertising them is expected. Confirm that authorization covers these methods, and that any not in use are turned off.`,
      evidence: `OPTIONS ${targetUrl}\nAllow: ${allow}`,
      solution: "Restrict HTTP methods to only those genuinely required. Use application-level authorization on any write methods. Block unused methods at the web server or load balancer before requests reach application code.",
      cweId: "CWE-650",
      cvssScore: 5.3,
      wstgId: "WSTG-CONF-06",
    }));
  }

  if (/\bCONNECT\b/i.test(allow)) {
    vulns.push(vuln({
      name: "HTTP CONNECT Method Enabled",
      severity: "medium",
      category: "HTTP Security",
      description: "The CONNECT method is advertised. This method is used to establish tunnels and could allow the server to be used as a proxy to reach internal systems not otherwise accessible.",
      evidence: `OPTIONS ${targetUrl}\nAllow: ${allow}`,
      solution: "Disable the CONNECT method unless you are intentionally running a proxy server.",
      cweId: "CWE-441",
      cvssScore: 6.1,
      wstgId: "WSTG-CONF-06",
    }));
  }

  return vulns;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ACTIVE CORS TESTING
// ─────────────────────────────────────────────────────────────────────────────

export async function checkActiveCors(targetUrl: string): Promise<ScanVulnerability[]> {
  const testOrigins = [
    "https://evil-attacker.com",
    "null",
  ];

  for (const origin of testOrigins) {
    const result = await safeGet(targetUrl, {
      headers: { Origin: origin },
      redirect: "follow",
    });
    if (!result) continue;

    const acao = result.headers["access-control-allow-origin"];
    const acac = result.headers["access-control-allow-credentials"];
    if (!acao) continue;

    const reflectsOrigin = acao === origin;
    const withCredentials = /^true$/i.test(acac ?? "");

    if (reflectsOrigin && withCredentials) {
      return [vuln({
        name: "CORS Misconfiguration — Credentials Allowed from Arbitrary Origin",
        severity: "critical",
        category: "CORS Misconfiguration",
        description: `The server reflects any request Origin in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true. This allows any malicious website to make authenticated cross-origin requests on behalf of a logged-in victim — reading their private data, performing actions as them, and effectively bypassing SameSite cookie protections.`,
        evidence: `GET ${targetUrl}\nRequest header: Origin: ${origin}\nResponse: Access-Control-Allow-Origin: ${acao}\nResponse: Access-Control-Allow-Credentials: ${acac}`,
        solution: "Maintain a strict server-side allowlist of trusted origins. Never dynamically reflect the incoming Origin header without validating it against the allowlist. Never combine a dynamic origin with credentials: true.",
        cweId: "CWE-942",
        cvssScore: 9.1,
        wstgId: "WSTG-CONF-07",
      })];
    }

    if (reflectsOrigin && !withCredentials) {
      // Without Allow-Credentials the browser sends no cookies, so this only
      // exposes what the tested URL already serves to anyone. Only that one URL
      // was tested, so the wording stays at what was observed.
      return [vuln({
        name: "CORS — Origin Reflected Without Credentials",
        severity: "low",
        category: "CORS Misconfiguration",
        description: `This URL reflects any Origin value in Access-Control-Allow-Origin without an allowlist, but does not set Access-Control-Allow-Credentials: true, so browsers will not attach cookies or other credentials to cross-origin requests. Only the tested URL was checked; if it (or other endpoints with the same policy) returns data that is not meant to be public, a third-party site could read it. Public content is not affected.`,
        evidence: `GET ${targetUrl}\nRequest header: Origin: ${origin}\nResponse: Access-Control-Allow-Origin: ${acao}\nResponse: Access-Control-Allow-Credentials: ${acac ?? "(absent)"}`,
        solution: "Validate the Origin header against an explicit allowlist for any endpoint that returns non-public data. Reflecting every origin is acceptable only for content that is public anyway.",
        cweId: "CWE-942",
        cvssScore: 3.7,
        wstgId: "WSTG-CONF-07",
        confidence: 75,
      })];
    }
  }

  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. OPEN REDIRECT TESTING
// ─────────────────────────────────────────────────────────────────────────────

export async function checkOpenRedirect(targetUrl: string): Promise<ScanVulnerability[]> {
  const base = new URL(targetUrl);
  const probeTarget = OPEN_REDIRECT_PROBE.template;
  const probeHost = new URL(probeTarget).hostname.toLowerCase();

  for (const param of OPEN_REDIRECT_PARAMS) {
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set(param, probeTarget);

    const result = await safeGet(testUrl.toString(), { redirect: "manual" });
    if (!result) continue;

    if (result.status >= 300 && result.status < 400) {
      const location = result.headers["location"] ?? "";
      // The host the browser would land on, not a substring match: a canonical
      // redirect or /login?next=<url> merely echoes the payload in its query.
      let landsOnProbe = false;
      try {
        landsOnProbe = new URL(location, testUrl).hostname.toLowerCase() === probeHost;
      } catch { /* unparseable Location */ }
      if (landsOnProbe) {
        return [vuln({
          name: "Open Redirect Vulnerability",
          severity: "medium",
          category: "Unvalidated Redirects",
          description: `The '${param}' parameter controls where users are sent after an action without validation. Attackers send victims a URL on ${base.hostname} (which they trust) that silently redirects them to a phishing site. This is widely used in credential harvesting campaigns because the initial URL appears legitimate.`,
          evidence: `GET ${testUrl.pathname}?${param}=${encodeURIComponent(probeTarget)}\nHTTP ${result.status}\nLocation: ${location}`,
          solution: "Validate all redirect targets against an allowlist of permitted paths or domains. Prefer relative paths. If external redirects are needed, use an intermediate confirmation page and never accept destination URLs from user input directly.",
          cweId: "CWE-601",
          cvssScore: 6.1,
          wstgId: "WSTG-CLNT-04",
        })];
      }
    }
  }

  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. CLICKJACKING VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Whether a browser blocks framing on these X-Frame-Options values, following
 * the HTML spec's processing: values are split on commas, lowercased and
 * de-duplicated, so "SAMEORIGIN, SAMEORIGIN" (an app and its proxy both adding
 * the header, joined by fetch) is plain SAMEORIGIN. Several different values
 * that include deny, sameorigin or allowall block framing outright. Anything
 * else on its own (ALLOW-FROM, which no current browser supports, or an
 * unknown word) is ignored, leaving the page frameable.
 */
export function xfoBlocksFraming(raw: string): boolean {
  const values = new Set(raw.split(",").map((v) => v.trim().toLowerCase()).filter(Boolean));
  if (values.size > 1) return ["deny", "sameorigin", "allowall"].some((v) => values.has(v));
  return values.has("deny") || values.has("sameorigin");
}

export async function checkClickjacking(targetUrl: string): Promise<ScanVulnerability[]> {
  // Only run if main scanner didn't already flag this via headers
  // This does a direct page fetch and checks the actual response headers
  const result = await safeGet(targetUrl, {}, 6_000);
  if (!result) return [];

  const xfo = result.headers["x-frame-options"];
  const csp = result.headers["content-security-policy"] ?? "";

  // A browser that supports CSP ignores X-Frame-Options entirely when the
  // enforced policy has frame-ancestors, so the header's value cannot leave the
  // page frameable. Legacy ALLOW-FROM kept next to frame-ancestors for old
  // browsers was reported as Medium here. A frame-ancestors that allows every
  // origin (`*`) protects nothing, so it does not excuse a broken header.
  if (cspRestrictsFraming(csp)) return [];

  // If both protections are missing, this is handled by the main scanner
  // But if X-Frame-Options is present but misconfigured:
  if (xfo && !xfoBlocksFraming(xfo)) {
    return [vuln({
      name: "X-Frame-Options Header Misconfigured",
      severity: "medium",
      category: "UI Security",
      description: `X-Frame-Options is set to an invalid or non-standard value: "${xfo}". Browsers may ignore unrecognized values, leaving the application vulnerable to clickjacking attacks where attackers embed your page in an invisible iframe.`,
      evidence: `GET ${targetUrl}\nX-Frame-Options: ${xfo}\n(valid values: DENY or SAMEORIGIN)`,
      solution: 'Set X-Frame-Options to either "DENY" (blocks all framing) or "SAMEORIGIN" (allows framing by same origin). Alternatively, use CSP: Content-Security-Policy: frame-ancestors \'none\'',
      cweId: "CWE-1021",
      cvssScore: 4.3,
      wstgId: "WSTG-CLNT-09",
    })];
  }

  return [];
}

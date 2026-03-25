/**
 * Black-box HTTP security scanner.
 * Fetches the target URL and analyses headers, TLS, cookies, CORS,
 * and page content to produce a list of vulnerabilities.
 */

import { randomUUID } from "node:crypto";

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
}

const FETCH_TIMEOUT_MS = 20_000;

function vuln(
  partial: Omit<ScanVulnerability, "id">,
): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

function headerVal(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  const key = Object.keys(headers).find((k) => k.toLowerCase() === lower);
  return key ? headers[key] : undefined;
}

function detectTechnologies(headers: Record<string, string>, html: string): string[] {
  const techs = new Set<string>();

  const server = headerVal(headers, "server");
  if (server) {
    if (/nginx/i.test(server)) techs.add("Nginx");
    if (/apache/i.test(server)) techs.add("Apache");
    if (/iis/i.test(server)) techs.add("IIS");
    if (/cloudflare/i.test(server)) techs.add("Cloudflare");
    if (/vercel/i.test(server)) techs.add("Vercel");
    if (/fastly/i.test(server)) techs.add("Fastly");
    if (/litespeed/i.test(server)) techs.add("LiteSpeed");
  }

  const powered = headerVal(headers, "x-powered-by");
  if (powered) {
    if (/php/i.test(powered)) techs.add("PHP");
    if (/express/i.test(powered)) techs.add("Express.js");
    if (/asp\.net/i.test(powered)) techs.add("ASP.NET");
    if (/next\.js/i.test(powered)) techs.add("Next.js");
  }

  const cf = headerVal(headers, "cf-ray");
  if (cf) techs.add("Cloudflare");

  // Cookie-based detection
  const setCookie = headerVal(headers, "set-cookie") ?? "";
  if (/PHPSESSID/i.test(setCookie)) techs.add("PHP");
  if (/ASP\.NET_SessionId/i.test(setCookie)) techs.add("ASP.NET");
  if (/JSESSIONID/i.test(setCookie)) techs.add("Java");
  if (/laravel_session/i.test(setCookie)) techs.add("Laravel");
  if (/django/i.test(setCookie)) techs.add("Django");

  // HTML-based detection (first 50KB only)
  const snippet = html.slice(0, 50_000);
  if (/<meta[^>]*generator[^>]*wordpress/i.test(snippet)) techs.add("WordPress");
  if (/wp-content|wp-includes/i.test(snippet)) techs.add("WordPress");
  if (/shopify/i.test(snippet)) techs.add("Shopify");
  if (/next\/dist|_next\/static/i.test(snippet)) techs.add("Next.js");
  if (/nuxt/i.test(snippet)) techs.add("Nuxt.js");
  if (/<div id="app"/.test(snippet) || /vue\.js/i.test(snippet)) techs.add("Vue.js");
  if (/react-root|ReactDOM/i.test(snippet)) techs.add("React");
  if (/angular\.js|ng-app/i.test(snippet)) techs.add("Angular");
  if (/cdn\.tailwindcss|tailwind/i.test(snippet)) techs.add("Tailwind CSS");
  if (/bootstrap/i.test(snippet)) techs.add("Bootstrap");
  if (/jquery/i.test(snippet)) techs.add("jQuery");

  return [...techs];
}

function analyzeCookies(setCookieHeader: string | undefined): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];
  if (!setCookieHeader) return findings;

  // handle multiple Set-Cookie headers joined by newline (from node-fetch flattening)
  const cookies = setCookieHeader.split(/\n|,(?=[^;])/);

  for (const cookie of cookies) {
    if (!cookie.trim()) continue;
    const namePart = cookie.split(";")[0]?.split("=")[0]?.trim() ?? "cookie";

    if (!/secure/i.test(cookie)) {
      findings.push(vuln({
        name: "Cookie Missing Secure Flag",
        severity: "high",
        category: "Session Management",
        description: `The cookie "${namePart}" is set without the Secure flag, meaning it can be transmitted over unencrypted HTTP connections, making it susceptible to interception.`,
        evidence: `Set-Cookie: ${cookie.split(";")[0]?.trim()}; (no Secure flag)`,
        solution: "Add the Secure attribute to all cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
        cweId: "CWE-614",
        cvssScore: 6.5,
      }));
    }

    if (!/httponly/i.test(cookie)) {
      findings.push(vuln({
        name: "Cookie Missing HttpOnly Flag",
        severity: "medium",
        category: "Session Management",
        description: `The cookie "${namePart}" is set without the HttpOnly flag, allowing client-side JavaScript to access it. This enables session theft via XSS attacks.`,
        evidence: `Set-Cookie: ${cookie.split(";")[0]?.trim()}; (no HttpOnly flag)`,
        solution: "Add the HttpOnly attribute to all session cookies: Set-Cookie: name=value; HttpOnly; Secure; SameSite=Lax",
        cweId: "CWE-1004",
        cvssScore: 5.3,
      }));
    }

    if (!/samesite/i.test(cookie)) {
      findings.push(vuln({
        name: "Cookie Missing SameSite Attribute",
        severity: "medium",
        category: "CSRF Protection",
        description: `The cookie "${namePart}" lacks the SameSite attribute, making the application potentially vulnerable to Cross-Site Request Forgery (CSRF) attacks.`,
        evidence: `Set-Cookie: ${cookie.split(";")[0]?.trim()}; (no SameSite attribute)`,
        solution: "Set SameSite=Lax or SameSite=Strict on all cookies to prevent CSRF: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
        cweId: "CWE-352",
        cvssScore: 4.3,
      }));
    }
  }

  return findings;
}

export async function runScan(targetUrl: string, _tier: string): Promise<ScanResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let response: Response;
  let finalUrl = targetUrl;
  let html = "";

  try {
    response = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; VibeScan-Security-Bot/1.0; +https://vibescan.app/bot)",
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
    finalUrl = response.url || targetUrl;
    try { html = await response.text(); } catch { html = ""; }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to reach target URL: ${msg}`);
  } finally {
    clearTimeout(timeoutHandle);
  }

  const rawHeaders: Record<string, string> = {};
  response.headers.forEach((val, key) => {
    rawHeaders[key] = val;
  });

  const isHttps = finalUrl.startsWith("https://");
  const tlsGrade = isHttps ? "A" : null;
  const server = headerVal(rawHeaders, "server") ?? null;
  const technologies = detectTechnologies(rawHeaders, html);
  const requestDurationMs = Date.now() - startedAt;
  const vulnerabilities: ScanVulnerability[] = [];

  // ── TLS / HTTPS ───────────────────────────────────────────────────────
  if (!isHttps) {
    vulnerabilities.push(vuln({
      name: "No HTTPS / Plaintext HTTP",
      severity: "critical",
      category: "Transport Security",
      description: "The application is served over HTTP without TLS encryption. All data transmitted between the browser and the server—including passwords and session tokens—can be intercepted by any network observer.",
      evidence: `URL: ${finalUrl}`,
      solution: "Obtain a TLS certificate (free from Let's Encrypt) and redirect all HTTP traffic to HTTPS. Set up HSTS once HTTPS is working.",
      cweId: "CWE-319",
      cvssScore: 9.1,
    }));
  }

  // ── HTTP Strict-Transport-Security ────────────────────────────────────
  const hsts = headerVal(rawHeaders, "strict-transport-security");
  if (!hsts && isHttps) {
    vulnerabilities.push(vuln({
      name: "Missing HTTP Strict-Transport-Security (HSTS)",
      severity: "high",
      category: "Transport Security",
      description: "HSTS is not configured. Without it, browsers may initially connect over HTTP, exposing users to downgrade attacks and SSL stripping. HSTS tells browsers to only ever connect via HTTPS.",
      solution: "Add this header to all HTTPS responses: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      cweId: "CWE-523",
      cvssScore: 7.4,
    }));
  }

  // ── Content-Security-Policy ───────────────────────────────────────────
  const csp = headerVal(rawHeaders, "content-security-policy");
  if (!csp) {
    vulnerabilities.push(vuln({
      name: "Missing Content-Security-Policy (CSP)",
      severity: "high",
      category: "Injection Defense",
      description: "No Content-Security-Policy header was found. CSP is the primary browser-enforced defense against Cross-Site Scripting (XSS) attacks. Without it, injected scripts can run with full page privileges and steal session cookies or credentials.",
      solution: "Implement a strict CSP. A starting point: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'. Tighten over time using CSP violation reports.",
      cweId: "CWE-79",
      cvssScore: 7.2,
    }));
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    vulnerabilities.push(vuln({
      name: "Weak Content-Security-Policy (unsafe-inline / unsafe-eval)",
      severity: "medium",
      category: "Injection Defense",
      description: "The Content-Security-Policy header allows 'unsafe-inline' or 'unsafe-eval', which significantly weakens XSS protection. Attackers who achieve HTML injection can still execute scripts.",
      evidence: `CSP: ${csp}`,
      solution: "Replace 'unsafe-inline' with nonce-based or hash-based CSP directives. Avoid 'unsafe-eval' entirely. Use a CSP evaluator (csp-evaluator.withgoogle.com) to check your policy.",
      cweId: "CWE-79",
      cvssScore: 5.4,
    }));
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
      solution: "Add: X-Frame-Options: DENY (or SAMEORIGIN if you need to embed within your own domain). Alternatively use: Content-Security-Policy: frame-ancestors 'none'",
      cweId: "CWE-1021",
      cvssScore: 4.3,
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
      evidence: xcto ? `X-Content-Type-Options: ${xcto}` : undefined,
      solution: "Add to all responses: X-Content-Type-Options: nosniff",
      cweId: "CWE-16",
      cvssScore: 4.3,
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
      solution: "Add: Referrer-Policy: strict-origin-when-cross-origin (or 'no-referrer' for maximum privacy)",
      cweId: "CWE-200",
      cvssScore: 3.1,
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
      solution: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=(). Adjust based on what your app actually needs.",
      cweId: "CWE-16",
      cvssScore: 2.4,
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
      evidence: "Access-Control-Allow-Origin: *",
      solution: "Replace the wildcard with a specific allowlist of trusted origins: Access-Control-Allow-Origin: https://your-frontend.com. Never use * on endpoints that return user-specific data.",
      cweId: "CWE-942",
      cvssScore: 6.5,
    }));
  }

  // ── Server / Technology Disclosure ────────────────────────────────────
  if (server && /\d/.test(server)) {
    vulnerabilities.push(vuln({
      name: "Server Version Disclosure",
      severity: "info",
      category: "Information Disclosure",
      description: `The Server header reveals detailed software version information: "${server}". Attackers use this to look up CVEs for the exact version and craft targeted exploits.`,
      evidence: `Server: ${server}`,
      solution: "Configure your web server to omit version numbers from the Server header, or remove the header entirely. In Nginx: server_tokens off; In Apache: ServerTokens Prod; ServerSignature Off",
      cweId: "CWE-200",
    }));
  }

  const poweredBy = headerVal(rawHeaders, "x-powered-by");
  if (poweredBy) {
    vulnerabilities.push(vuln({
      name: "X-Powered-By Header Discloses Technology Stack",
      severity: "info",
      category: "Information Disclosure",
      description: `The X-Powered-By header advertises the underlying technology: "${poweredBy}". This helps attackers fingerprint your stack and search for known vulnerabilities.`,
      evidence: `X-Powered-By: ${poweredBy}`,
      solution: "Remove the X-Powered-By header. In Express.js: app.disable('x-powered-by'); In PHP: expose_php = Off in php.ini",
      cweId: "CWE-200",
    }));
  }

  // ── Cookie analysis ───────────────────────────────────────────────────
  const setCookie = headerVal(rawHeaders, "set-cookie");
  const cookieVulns = analyzeCookies(setCookie);
  vulnerabilities.push(...cookieVulns);

  // ── Mixed content ─────────────────────────────────────────────────────
  if (isHttps && /src=["']http:\/\//i.test(html.slice(0, 100_000))) {
    vulnerabilities.push(vuln({
      name: "Mixed Content (HTTP Resources on HTTPS Page)",
      severity: "medium",
      category: "Transport Security",
      description: "The HTTPS page loads resources (scripts, stylesheets, images) over plain HTTP. Browsers block or warn about mixed content, and the HTTP resources can be intercepted and modified by attackers.",
      solution: "Update all resource URLs to use HTTPS. Use protocol-relative URLs (//example.com/resource) or absolute HTTPS URLs. Enable Content-Security-Policy: upgrade-insecure-requests",
      cweId: "CWE-311",
      cvssScore: 5.9,
    }));
  }

  // ── X-XSS-Protection (deprecated but useful to flag if set wrong) ─────
  const xxss = headerVal(rawHeaders, "x-xss-protection");
  if (xxss && xxss.trim() === "0") {
    vulnerabilities.push(vuln({
      name: "XSS Auditor Disabled (X-XSS-Protection: 0)",
      severity: "info",
      category: "Injection Defense",
      description: "X-XSS-Protection is explicitly set to 0, which disables the browser's built-in XSS auditor (in older browsers). While modern browsers have deprecated this header, setting it to 0 provides no benefit and may confuse automated scanners.",
      evidence: "X-XSS-Protection: 0",
      solution: "Either remove the header entirely (recommended for modern browsers) or set X-XSS-Protection: 1; mode=block. Rely on CSP for actual XSS protection.",
    }));
  }

  return {
    targetUrl,
    finalUrl,
    statusCode: response.status,
    server,
    tlsGrade,
    technologies,
    vulnerabilities,
    requestDurationMs,
    rawHeaders,
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

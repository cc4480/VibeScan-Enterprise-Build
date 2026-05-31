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
async function isHstsPreloaded(hostname: string): Promise<boolean> {
  const apex = hostname.replace(/^www\./, "");

  // ── hstspreload.org tracking API ─────────────────────────────────────────
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
      if (json.status === "preloaded") return true;
      // "pending" means submitted but not yet active — don't suppress
    }
  } catch { /* fall through */ }

  return false;
}

import { runAllProbes } from "./probes";
import { checkDnsSecurity } from "./dnsChecks";
import { scanJavaScriptForSecrets } from "./jsScanner";
import { crawlAndCheck } from "./crawler";
import { checkForKnownVulnerabilities, extractVersionedTechnologies } from "./cveCheck";
import { analyzeJwts } from "./jwtAnalysis";
import { checkSubdomainTakeover } from "./subdomainTakeover";
import { checkPathTraversal } from "./pathTraversal";
import { checkSourceMaps } from "./sourceMaps";
import { autoEnrichConfidence } from "./scoring";
import { runBaasProbes } from "./baasProbes";
import { runGraphqlProbe } from "./graphqlProbe";
import { runApiDocsProbe } from "./apiDocsProbe";
import { runNextjsProbe } from "./nextjsProbe";
import { runStorageProbe } from "./storageProbe";

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

function detectTechnologies(headers: Record<string, string>, html: string): string[] {
  const techs = new Set<string>();

  // ── Server header ────────────────────────────────────────────────────
  const server = headerVal(headers, "server") ?? "";
  if (/nginx/i.test(server))                      techs.add("Nginx");
  if (/apache/i.test(server))                     techs.add("Apache");
  if (/microsoft-iis/i.test(server))              techs.add("IIS");
  if (/cloudflare/i.test(server))                 techs.add("Cloudflare");
  if (/vercel/i.test(server))                     techs.add("Vercel");
  if (/fastly/i.test(server))                     techs.add("Fastly");
  if (/litespeed/i.test(server))                  techs.add("LiteSpeed");
  if (/openresty/i.test(server))                  techs.add("OpenResty");
  if (/caddy/i.test(server))                      techs.add("Caddy");
  if (/gunicorn/i.test(server))                   techs.add("Gunicorn");
  if (/unicorn/i.test(server))                    techs.add("Unicorn");
  if (/cowboy/i.test(server))                     techs.add("Cowboy");
  if (/kestrel/i.test(server))                    techs.add("Kestrel (.NET)");
  if (/gfe|google frontend/i.test(server))        techs.add("Google Cloud / GFE");
  if (/aws|amazon/i.test(server))                 techs.add("AWS");
  if (/envoy/i.test(server))                      techs.add("Envoy Proxy");
  if (/netlify/i.test(server))                    techs.add("Netlify");
  if (/squarespace/i.test(server))                techs.add("Squarespace");
  if (/ghost/i.test(server))                      techs.add("Ghost");
  if (/webflow/i.test(server))                    techs.add("Webflow");

  // ── CDN / infrastructure headers ─────────────────────────────────────
  if (headerVal(headers, "cf-ray"))               techs.add("Cloudflare");
  if (headerVal(headers, "cf-cache-status"))      techs.add("Cloudflare");
  if (headerVal(headers, "x-vercel-id"))          techs.add("Vercel");
  if (headerVal(headers, "x-netlify"))            techs.add("Netlify");
  if (headerVal(headers, "x-amz-cf-id") || headerVal(headers, "x-amz-request-id")) techs.add("AWS CloudFront");
  if (headerVal(headers, "x-azure-ref"))          techs.add("Azure");
  if (headerVal(headers, "x-ms-request-id"))      techs.add("Azure");
  if (headerVal(headers, "x-github-request-id"))  techs.add("GitHub Pages");
  if (headerVal(headers, "x-fastly-request-id"))  techs.add("Fastly");
  if (headerVal(headers, "fly-request-id"))       techs.add("Fly.io");
  if (headerVal(headers, "x-railway-request-id")) techs.add("Railway");
  if (headerVal(headers, "x-render-origin-server")) techs.add("Render");
  if (headerVal(headers, "x-served-by"))          techs.add("Fastly");
  if (headerVal(headers, "x-cache")) {
    const xc = headerVal(headers, "x-cache") ?? "";
    if (/cloudfront/i.test(xc))                   techs.add("AWS CloudFront");
  }
  const via = headerVal(headers, "via") ?? "";
  if (/cloudfront/i.test(via))                    techs.add("AWS CloudFront");
  if (/varnish/i.test(via))                       techs.add("Varnish Cache");
  if (/squid/i.test(via))                         techs.add("Squid Proxy");

  // ── X-Powered-By ─────────────────────────────────────────────────────
  const powered = headerVal(headers, "x-powered-by") ?? "";
  if (/php/i.test(powered))                       techs.add("PHP");
  if (/express/i.test(powered))                   techs.add("Express.js");
  if (/asp\.net/i.test(powered))                  techs.add("ASP.NET");
  if (/next\.js/i.test(powered))                  techs.add("Next.js");
  if (/nuxt/i.test(powered))                      techs.add("Nuxt.js");
  if (/django/i.test(powered))                    techs.add("Django");
  if (/rails/i.test(powered))                     techs.add("Ruby on Rails");

  // ── Framework-specific headers ───────────────────────────────────────
  if (headerVal(headers, "x-drupal-cache") || headerVal(headers, "x-drupal-dynamic-cache")) techs.add("Drupal");
  if (headerVal(headers, "x-wordpress-cache") || headerVal(headers, "x-wp-cf-super-cache")) techs.add("WordPress");
  if (headerVal(headers, "x-shopify-stage") || headerVal(headers, "x-shopid"))              techs.add("Shopify");
  if (headerVal(headers, "x-wix-request-id"))     techs.add("Wix");
  if (headerVal(headers, "x-squarespace-cache"))  techs.add("Squarespace");
  if (headerVal(headers, "x-ghost-cache-status")) techs.add("Ghost");

  // Generator / Link headers
  const link = headerVal(headers, "link") ?? "";
  if (/wp-json|wp\.me/i.test(link))               techs.add("WordPress");
  if (/api\.ghost\.org/i.test(link))              techs.add("Ghost");
  const generator = headerVal(headers, "x-generator") ?? "";
  if (/drupal/i.test(generator))                  techs.add("Drupal");
  if (/wordpress/i.test(generator))               techs.add("WordPress");

  // ── Cookie-based detection ───────────────────────────────────────────
  const setCookie = headerVal(headers, "set-cookie") ?? "";
  if (/PHPSESSID/i.test(setCookie))               techs.add("PHP");
  if (/ASP\.NET_SessionId/i.test(setCookie))      techs.add("ASP.NET");
  if (/JSESSIONID/i.test(setCookie))              techs.add("Java / Servlet");
  if (/laravel_session/i.test(setCookie))         techs.add("Laravel");
  if (/csrftoken|sessionid/i.test(setCookie))     techs.add("Django");
  if (/rack\.session/i.test(setCookie))           techs.add("Ruby on Rails");
  if (/shopify/i.test(setCookie))                 techs.add("Shopify");
  if (/__stripe/i.test(setCookie))                techs.add("Stripe");

  // ── HTML-based detection (first 80KB) ───────────────────────────────
  const s = html.slice(0, 80_000);

  // CMS platforms
  if (/<meta[^>]*generator[^>]*wordpress/i.test(s) || /wp-content|wp-includes|wpemoji/i.test(s))  techs.add("WordPress");
  if (/<meta[^>]*generator[^>]*drupal/i.test(s) || /drupal\.settings|Drupal\.behaviors/i.test(s)) techs.add("Drupal");
  if (/<meta[^>]*generator[^>]*joomla/i.test(s) || /\/media\/jui\//i.test(s))                     techs.add("Joomla");
  if (/<meta[^>]*generator[^>]*ghost/i.test(s) || /ghost\.org|content="Ghost/i.test(s))           techs.add("Ghost");
  if (/shopify\.com|cdn\.shopify\.com|Shopify\.theme/i.test(s))                                   techs.add("Shopify");
  if (/squarespace\.com|squarespace-cdn|data-squarespace/i.test(s))                               techs.add("Squarespace");
  if (/wix\.com|static\.wixstatic|wixsite\.com/i.test(s))                                         techs.add("Wix");
  if (/webflow\.com|uploads-ssl\.webflow/i.test(s))                                               techs.add("Webflow");

  // JS frameworks
  if (/_next\/static|__NEXT_DATA__|next\/dist/i.test(s))                                          techs.add("Next.js");
  if (/__nuxt__|nuxt\.js|_nuxt\//i.test(s))                                                       techs.add("Nuxt.js");
  if (/gatsby|___gatsby|__GATSBY/i.test(s))                                                       techs.add("Gatsby");
  if (/data-reactroot|ReactDOM|react\.development|react\.production|__react_/i.test(s))           techs.add("React");
  if (/__vue_app__|data-v-[a-f0-9]{8}|Vue\.version|vue\.min\.js/i.test(s))                        techs.add("Vue.js");
  if (/ng-version|ng-app|angular\.js|angular\.min\.js|platformBrowserDynamic/i.test(s))           techs.add("Angular");
  if (/svelte-[a-z0-9]+|__svelte|SvelteKit/i.test(s))                                             techs.add("Svelte");
  if (/__remixContext|remix-manifest/i.test(s))                                                    techs.add("Remix");
  if (/astro-island|astro-root/i.test(s))                                                         techs.add("Astro");
  if (/data-ember-|emberjs|Ember\.VERSION/i.test(s))                                              techs.add("Ember.js");
  if (/backbone\.js|Backbone\.View/i.test(s))                                                     techs.add("Backbone.js");

  // CSS frameworks
  if (/tailwindcss|tw-|class="[^"]*\b(?:flex|grid|px-|py-|text-|bg-|rounded)[^"]*"/i.test(s))    techs.add("Tailwind CSS");
  if (/bootstrap\.min\.css|bootstrap\.css|class="[^"]*\b(?:container|row|col-)/i.test(s))        techs.add("Bootstrap");
  if (/bulma\.css|class="[^"]*\b(?:columns|column\s+is-)/i.test(s))                              techs.add("Bulma");

  // JS libraries
  if (/jquery[.-][0-9]|jquery\.min\.js|jQuery\.fn/i.test(s))                                     techs.add("jQuery");
  if (/lodash\.js|lodash\.min|_\.version/i.test(s))                                               techs.add("Lodash");
  if (/alpinejs|x-data=|x-show=/i.test(s))                                                        techs.add("Alpine.js");
  if (/htmx\.org|hx-get|hx-post/i.test(s))                                                        techs.add("HTMX");

  // Analytics & tracking
  if (/google-analytics\.com|gtag\(|ga\.js|GoogleAnalyticsObject/i.test(s))                      techs.add("Google Analytics");
  if (/googletagmanager\.com\/gtm/i.test(s))                                                      techs.add("Google Tag Manager");
  if (/plausible\.io|data-domain/i.test(s) && /plausible/i.test(s))                              techs.add("Plausible Analytics");
  if (/mixpanel\.com|mixpanel\.init/i.test(s))                                                    techs.add("Mixpanel");
  if (/segment\.com|analytics\.load|analytics\.page/i.test(s))                                   techs.add("Segment");
  if (/hotjar\.com|hjid/i.test(s))                                                                techs.add("Hotjar");
  if (/intercom\.io|intercomSettings/i.test(s))                                                   techs.add("Intercom");
  if (/js\.stripe\.com|Stripe\(/i.test(s))                                                        techs.add("Stripe");
  if (/sentry\.io|Sentry\.init/i.test(s))                                                         techs.add("Sentry");

  // Static site generators (meta generator tag)
  if (/<meta[^>]*generator[^>]*hugo/i.test(s))                                                    techs.add("Hugo");
  if (/<meta[^>]*generator[^>]*jekyll/i.test(s))                                                  techs.add("Jekyll");
  if (/<meta[^>]*generator[^>]*eleventy/i.test(s))                                                techs.add("Eleventy");
  if (/<meta[^>]*generator[^>]*hexo/i.test(s))                                                    techs.add("Hexo");

  // Language indicators from error messages / comments
  if (/python|django|flask|fastapi/i.test(s) && techs.size === 0)                                 techs.add("Python");
  if (/ruby on rails|rack/i.test(s) && !techs.has("Ruby on Rails"))                              techs.add("Ruby on Rails");

  return [...techs];
}

// Cookies set by third-party infrastructure (CDN proxies, load balancers, etc.)
// that the site owner has no ability to modify.  Flagging these produces
// unfixable false positives — the fix would require contacting the infra vendor.
const INFRA_COOKIE_NAMES = new Set([
  "gaesa",      // Replit CDN / proxy
  "__cf_bm",    // Cloudflare Bot Management
  "__cflb",     // Cloudflare Load Balancing
  "_cfuvid",    // Cloudflare UVID
  "cf_clearance", // Cloudflare challenge clearance
  "__utmz",     // Google Analytics (legacy)
  "__utma",     // Google Analytics (legacy)
  "_ga",        // Google Analytics
  "_gid",       // Google Analytics
  "_gat",       // Google Analytics throttle
]);

function analyzeCookies(setCookieHeader: string | undefined): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];
  if (!setCookieHeader) return findings;

  const cookies = setCookieHeader.split(/\n|,(?=[^;])/);

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

    if (!/secure/i.test(cookie)) {
      findings.push(vuln({
        name: "Cookie Missing Secure Flag",
        severity: "high",
        category: "Session Management",
        description: `The cookie "${namePart}" is set without the Secure flag, meaning it can be transmitted over unencrypted HTTP connections, making it susceptible to interception.`,
        evidence: `Set-Cookie: ${cookie.trim()}`,
        solution: "Add the Secure attribute to all cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
        cweId: "CWE-614",
        cvssScore: 6.5,
        wstgId: "WSTG-SESS-02",
      }));
    }

    if (!/httponly/i.test(cookie)) {
      findings.push(vuln({
        name: "Cookie Missing HttpOnly Flag",
        severity: "medium",
        category: "Session Management",
        description: `The cookie "${namePart}" is set without the HttpOnly flag, allowing client-side JavaScript to access it. This enables session theft via XSS attacks.`,
        evidence: `Set-Cookie: ${cookie.trim()}`,
        solution: "Add the HttpOnly attribute to all session cookies: Set-Cookie: name=value; HttpOnly; Secure; SameSite=Lax",
        cweId: "CWE-1004",
        cvssScore: 5.3,
        wstgId: "WSTG-SESS-02",
      }));
    }

    if (!/samesite/i.test(cookie)) {
      findings.push(vuln({
        name: "Cookie Missing SameSite Attribute",
        severity: "medium",
        category: "CSRF Protection",
        description: `The cookie "${namePart}" lacks the SameSite attribute, making the application potentially vulnerable to Cross-Site Request Forgery (CSRF) attacks.`,
        evidence: `Set-Cookie: ${cookie.trim()}`,
        solution: "Set SameSite=Lax or SameSite=Strict on all cookies to prevent CSRF: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax",
        cweId: "CWE-352",
        cvssScore: 4.3,
        wstgId: "WSTG-SESS-02",
      }));
    }
  }

  return findings;
}

export async function runScan(targetUrl: string, tier: string): Promise<ScanResult> {
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
        "Cache-Control": "no-cache, no-store",
        "Pragma": "no-cache",
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
  if (!csp) {
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
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    vulnerabilities.push(vuln({
      name: "Weak Content-Security-Policy (unsafe-inline / unsafe-eval)",
      severity: "medium",
      category: "Injection Defense",
      description: "The Content-Security-Policy header allows 'unsafe-inline' or 'unsafe-eval', which significantly weakens XSS protection. Attackers who achieve HTML injection can still execute scripts.",
      evidence: `GET ${finalUrl}\nContent-Security-Policy: ${csp}`,
      solution: "Replace 'unsafe-inline' with nonce-based or hash-based CSP directives. Avoid 'unsafe-eval' entirely. Use a CSP evaluator (csp-evaluator.withgoogle.com) to check your policy.",
      cweId: "CWE-79",
      cvssScore: 5.4,
      wstgId: "WSTG-CONF-12",
    }));
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

    // Wildcard script-src defeats the entire point of CSP
    if (/script-src\s+[^;]*\*/.test(csp)) {
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
  vulnerabilities.push(...analyzeCookies(setCookie));

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

  // ── X-XSS-Protection (deprecated but flag if disabled) ────────────────
  const xxss = headerVal(rawHeaders, "x-xss-protection");
  if (xxss && xxss.trim() === "0") {
    vulnerabilities.push(vuln({
      name: "XSS Auditor Disabled (X-XSS-Protection: 0)",
      severity: "info",
      category: "Injection Defense",
      description: "X-XSS-Protection is explicitly set to 0, which disables the browser's built-in XSS auditor (in older browsers). While modern browsers have deprecated this header, setting it to 0 provides no benefit and may confuse automated scanners.",
      evidence: `GET ${finalUrl}\nX-XSS-Protection: 0`,
      solution: "Either remove the header entirely (recommended for modern browsers) or set X-XSS-Protection: 1; mode=block. Rely on CSP for actual XSS protection.",
      wstgId: "WSTG-CLNT-01",
    }));
  }

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

  // ── Run all parallel probes ───────────────────────────────────────────
  // All checks run concurrently — active HTTP probes, DNS checks, site crawl,
  // CVE lookup, JWT analysis, subdomain takeover, and (deep only) JS secret
  // scanning and path traversal.
  // Run crawl separately to capture pagesVisited alongside findings
  const crawlPromise = crawlAndCheck(
    finalUrl, html, rawHeaders, tier === "deep" ? 20 : 0,
  ).catch(() => ({ vulnerabilities: [], pagesVisited: [], probedNotFound: [] }));

  const probePromises: Promise<ScanVulnerability[]>[] = [
    runAllProbes(finalUrl, html).catch(() => []),
    checkDnsSecurity(finalUrl).catch(() => []),
    checkForKnownVulnerabilities(html, rawHeaders).catch(() => []),
    // Passive JWT analysis — no extra HTTP requests
    analyzeJwts(rawHeaders, html).catch(() => []),
    // Subdomain takeover — 1-2 DNS + HTTP checks
    checkSubdomainTakeover(finalUrl).catch(() => []),
    // Source map exposure — checks JS bundles for .map files
    checkSourceMaps(html, finalUrl).catch(() => []),
    // BaaS open-data checks: Supabase RLS, PocketBase, Appwrite, Firebase Firestore
    runBaasProbes(finalUrl, html).catch(() => []),
    // GraphQL introspection + field suggestions
    runGraphqlProbe(finalUrl, html).catch(() => []),
    // Exposed API docs: Swagger/OpenAPI/ReDoc
    runApiDocsProbe(finalUrl).catch(() => []),
    // Next.js __NEXT_DATA__ prop leaks
    runNextjsProbe(finalUrl, html).catch(() => []),
    // Public cloud storage listing: S3, GCS, Azure Blob
    runStorageProbe(finalUrl, html).catch(() => []),
  ];

  if (tier === "deep") {
    probePromises.push(
      scanJavaScriptForSecrets(html, finalUrl).catch(() => []),
      // Active path traversal probing — multiple HTTP requests
      checkPathTraversal(finalUrl, html).catch(() => []),
    );
  }

  const [crawlResult, ...probeResults] = await Promise.all([
    crawlPromise,
    Promise.allSettled(probePromises),
  ]);

  vulnerabilities.push(...crawlResult.vulnerabilities);
  const settledProbes = probeResults[0] as PromiseSettledResult<ScanVulnerability[]>[];
  for (const result of settledProbes) {
    if (result.status === "fulfilled") {
      vulnerabilities.push(...result.value);
    }
  }

  return {
    targetUrl,
    finalUrl,
    statusCode: response.status,
    server,
    tlsGrade,
    technologies,
    vulnerabilities: autoEnrichConfidence(vulnerabilities),
    requestDurationMs,
    rawHeaders,
    pagesScanned: crawlResult.pagesVisited,
    probedNotFound: crawlResult.probedNotFound,
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

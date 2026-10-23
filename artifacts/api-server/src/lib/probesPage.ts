/** Probes that read the page and its transport: error disclosure, HTTPS redirect, rate limiting. */
import type { ScanVulnerability } from "./scanner";
import { vuln, safeGet } from "./probesCore";
import { hstsPreloadApiUrl } from "./scannerHstsPreload";

// ─────────────────────────────────────────────────────────────────────────────
// 7. ERROR PAGE DISCLOSURE
// ─────────────────────────────────────────────────────────────────────────────

export async function checkErrorDisclosure(baseUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  const testPath = `/_vibescan-${Date.now()}-not-a-real-path`;
  const result = await safeGet(`${origin}${testPath}`);
  if (!result) return [];

  const body = result.body;

  // Baseline against the real homepage before trusting any match. There is no
  // status-code shortcut here: a genuine PHP leak is frequently a Warning: or
  // Notice: printed inline into an otherwise-200 response, so requiring a 4xx
  // or 5xx would create false negatives on the exact case this exists to
  // catch. And two of the patterns below — "Warning:" and "Notice:" bare — are
  // short enough to appear as ordinary UI copy (an age gate, a shipping
  // notice), which an SPA catch-all would then return with status 200 for
  // this deliberately-nonexistent path exactly as it would for any other
  // unmatched route. The baseline is what tells those two apart: content the
  // homepage already carries is not a leak specific to this path.
  const homepage = await safeGet(origin);
  const baselineBody = homepage?.body ?? "";

  const leakPatterns: Array<{ rx: RegExp; name: string }> = [
    { rx: /at\s+\w[\w.]+\s+\((?:\/[\w./\\-]+|[A-Z]:\\[\w./\\-]+):\d+:\d+\)/m, name: "JavaScript/Node.js stack trace with file paths" },
    { rx: /Traceback \(most recent call last\)[\s\S]{0,200}File "\/[^"]+"/m, name: "Python traceback with system file paths" },
    { rx: /in \/[\w./\\-]+\.php on line \d+/m, name: "PHP error with file path" },
    // Structural, like the three above it. This used to be
    // /Parse error:|Fatal error:|Warning:|Notice:/ — a bare English word and a
    // colon — so "Privacy Notice:" or "Legal Notice:" in ordinary page copy was
    // reported as a leaked PHP error. linkedin.com, which is Java and serves
    // JSESSIONID, was flagged for a PHP error on its 404 page.
    //
    // Each alternative below is a shape PHP actually emits and prose does not:
    // a parse error names "syntax error", a fatal error is "Uncaught", and a
    // warning or notice either names the failing function call or an undefined
    // symbol. Errors that DO carry a file path are matched by the pattern above.
    {
      rx: /(?:Parse error:\s*syntax error|Fatal error:\s*Uncaught|(?:Warning|Notice|Deprecated):\s+(?:Undefined\s+(?:variable|index|offset|array key|property)|\w+\(\):))/m,
      name: "PHP error message",
    },
    { rx: /ActiveRecord::\w+|ActionController::\w+/m, name: "Ruby on Rails exception class" },
    { rx: /\bat [\w.$]+\([\w$.]+\.java:\d+\)/m, name: "Java stack trace" },
    { rx: /System\.(NullReference|InvalidOperation|Web\.Http)Exception/m, name: "ASP.NET exception" },
    { rx: /werkzeug\.debug|Debugger caught an exception/m, name: "Werkzeug/Flask debugger (CRITICAL — allows RCE via debug console)" },
    { rx: /Whoops\\|Symfony\\Component\\Debug\\Exception/m, name: "PHP Whoops/Symfony debug page" },
    { rx: /DebugException|Illuminate\\Foundation\\Exceptions/m, name: "Laravel debug page" },
    { rx: /Django.*DEBUG.*True|django\.core\.exceptions/m, name: "Django debug page (DEBUG=True in production)" },
  ];

  const matched = leakPatterns.find((p) => p.rx.test(body) && !p.rx.test(baselineBody));
  if (!matched) return [];

  const isFlaskDebugger = /werkzeug\.debug|Debugger caught/.test(body);

  return [vuln({
    name: isFlaskDebugger
      ? "Flask/Werkzeug Interactive Debugger Exposed (Remote Code Execution)"
      : "Verbose Error Pages Expose Internal Application Details",
    severity: isFlaskDebugger ? "critical" : "medium",
    category: "Information Disclosure",
    description: isFlaskDebugger
      ? "The Flask/Werkzeug interactive debugger is enabled and publicly accessible. This allows ANYONE to execute arbitrary Python code on your server directly from their browser. This is a complete server compromise."
      : `Non-existent URLs trigger error pages containing ${matched.name}. These responses reveal internal file paths, framework/library versions, function call stacks, and application structure—dramatically reducing attacker effort to find exploitable weaknesses.`,
    evidence: `GET ${origin}${testPath} → HTTP ${result.status}\nLeak type: ${matched.name}`,
    solution: isFlaskDebugger
      ? "IMMEDIATELY disable the Werkzeug debugger: set DEBUG=False and FLASK_ENV=production. This is a critical emergency—your server can be fully compromised."
      : "Disable debug mode in production. Use a generic error page that reveals nothing. Log detailed errors server-side only. Framework guides: Express.js — use a production error handler middleware. Django — DEBUG = False. PHP — display_errors = Off in php.ini. Rails — config.consider_all_requests_local = false.",
    cweId: isFlaskDebugger ? "CWE-94" : "CWE-209",
    cvssScore: isFlaskDebugger ? 10.0 : 5.3,
    wstgId: "WSTG-CONF-02",
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. HTTP → HTTPS REDIRECT CHECK
// ─────────────────────────────────────────────────────────────────────────────

export async function checkHttpsRedirect(targetUrl: string): Promise<ScanVulnerability[]> {
  let hostname: string;
  try {
    const parsed = new URL(targetUrl);
    // This check only runs when the scan target is already HTTPS, meaning HTTPS
    // is available and working. A missing redirect is therefore MEDIUM (not HIGH):
    // the site has HTTPS, it just doesn't force HTTP visitors over to it.
    // HIGH ("no HTTPS at all") is handled in scanner.ts.
    if (parsed.protocol !== "https:") return [];
    hostname = parsed.hostname;
  } catch {
    return [];
  }

  // Follow redirects automatically. Node.js fetch with redirect:"manual" returns
  // an opaque redirect (status 0, no headers) so we can't read the Location header.
  // Using redirect:"follow" and inspecting the final URL is simpler and reliable.
  // Retried once, because a single miss here is silent and consequential. Under
  // the concurrency of a full scan this request competes with every other probe
  // hitting the same host, and one timeout used to mean the finding simply
  // vanished from the report — verified on archive.org, which genuinely serves
  // plain HTTP with no redirect, reported it on 2026-09-08, and then did not on
  // the 2026-09-19 re-run while the same check called in isolation reported it
  // three times out of three.
  //
  // Still fails open if BOTH attempts fail: a network error is not evidence that
  // a redirect is missing, and claiming one would be a false positive. The
  // difference is that a transient blip no longer costs a true finding, and a
  // genuine failure to check now surfaces in the scan-coverage note rather than
  // reading as "checked, fine".
  // HTTP_REDIRECT_PROBE_URL replaces the plain-HTTP address that is requested (port 80 of the host), so a test can serve it.
  const plainUrl = process.env["HTTP_REDIRECT_PROBE_URL"] || `http://${hostname}/`;
  let result = await safeGet(plainUrl, { redirect: "follow" }, 8_000);
  if (!result) {
    result = await safeGet(plainUrl, { redirect: "follow" }, 8_000);
  }
  if (!result) {
    throw new Error(`could not reach http://${hostname}/ to test the HTTPS redirect`);
  }

  // If the final URL landed on HTTPS, the redirect chain is in place — all good.
  if (result.finalUrl.startsWith("https://")) return [];

  // Before filing a finding, verify the domain is not on the HSTS preload list.
  // Preloaded domains rely on browsers enforcing HTTPS natively — they intentionally
  // omit HTTP-level redirects and this is NOT a vulnerability.

  // Fast path: Chrome built-in preloaded domains not tracked by hstspreload.org
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
  const apex = hostname.replace(/^www\./, "");
  if (CHROME_BUILTIN_PRELOADED.has(apex)) return [];

  try {
    const preloadRes = await safeGet(
      `${hstsPreloadApiUrl()}?domain=${encodeURIComponent(apex)}`,
      {},
      5_000,
    );
    if (preloadRes && /"status"\s*:\s*"preloaded"/.test(preloadRes.body)) {
      return []; // domain is HSTS-preloaded — not a vulnerability
    }
  } catch { /* fail open — don't suppress on network error */ }

  return [vuln({
    name: "HTTP Traffic Not Redirected to HTTPS",
    severity: "medium",
    category: "Transport Security",
    description: `The HTTP version of the site does not issue a redirect to HTTPS. Users arriving via plain HTTP (old bookmarks, typed URLs, email links) may communicate in plaintext.`,
    evidence: `GET http://${hostname}/ (followed up to 5 redirect hops)\nResult: request chain never reached https://${hostname}/\nHSTS preload list: not preloaded`,
    solution: "Add a permanent 301 redirect from HTTP to HTTPS at the web server or load balancer:\n  Nginx: return 301 https://$host$request_uri;\n  Apache: Redirect permanent / https://yourdomain.com/\nAlternatively, submit your domain to the HSTS preload list (https://hstspreload.org) so browsers enforce HTTPS natively.",
    cweId: "CWE-319",
    cvssScore: 5.3,
    wstgId: "WSTG-CONF-07",
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. RATE LIMITING DETECTION
// ─────────────────────────────────────────────────────────────────────────────

export async function checkRateLimiting(targetUrl: string): Promise<ScanVulnerability[]> {
  const result = await safeGet(targetUrl, {}, 6_000);
  if (!result) return [];

  const h = result.headers;
  const hasRateLimit =
    // Standard rate-limit response headers (RFC 6585 / IETF draft)
    h["x-ratelimit-limit"] ||
    h["x-rate-limit-limit"] ||
    h["ratelimit-limit"] ||
    h["retry-after"] ||
    h["x-ratelimit-remaining"] ||
    h["ratelimit-remaining"] ||
    // API gateway / proxy headers
    h["x-kong-limit"] ||
    h["x-envoy-ratelimited"] ||
    // Enterprise CDN / infrastructure — these platforms enforce rate limiting
    // at the infrastructure level and don't always expose headers for it.
    h["cf-ray"] ||                                          // Cloudflare
    h["x-akamai-request-id"] || h["akamai-grn"] ||         // Akamai WAF
    h["x-amz-cf-id"] ||                                    // AWS CloudFront
    // Google fronts different products with different server tokens: `gws`
    // (web search), `gfe` (Google Front End), `ESF` (API frontend), `sffe`
    // (static content), `Golfe2`. Only `gfe` was listed, so google.com itself —
    // which answers `Server: gws` — was reported as having no rate limiting.
    /^(gws|gfe|esf|sffe|golfe)/i.test(h["server"] ?? "") ||
    /google-cloud|google-edge|google frontend/i.test(h["server"] ?? "") ||
    /google/i.test(h["via"] ?? "") ||                       // Google infra
    /cloudfront/i.test(h["x-cache"] ?? "") ||               // CloudFront cache
    // GitHub's own edge. Same category as the CDNs above: rate limiting is
    // enforced at the infrastructure tier and the HTML responses carry no
    // rate-limit headers, so github.com was reported as having none at all.
    h["x-github-edge-region"] || h["x-github-request-id"] ||
    h["x-azure-ref"] || h["x-ms-ref"] ||                   // Azure Front Door / CDN
    /akamai/i.test(h["x-check-cacheable"] ?? "");           // Akamai edge

  if (!hasRateLimit) {
    return [vuln({
      // Renamed from "No Rate Limiting Detected", which asserted something this
      // check cannot observe. A passive GET of a homepage sees response headers
      // and nothing else; rate limiting normally lives on login and API routes
      // and normally advertises nothing. Across a 30-site corpus this fired on
      // 15, including Stripe, Wikipedia and GOV.UK — stripe.com sends no
      // rate-limit headers whatsoever and unquestionably rate-limits. The
      // allowlist above had already been patched twice, for Google server
      // tokens and for GitHub's edge, which is the shape of a check chasing an
      // unobservable property one vendor at a time.
      //
      // It now says only what was seen, at INFO, which carries weight 0 in
      // computeRiskScore — a site cannot be graded worse for declining to
      // publish its throttling policy.
      name: "Rate Limiting Not Advertised in Response Headers",
      severity: "info",
      category: "Brute Force Protection",
      description: "No rate-limit headers were present on this response. That is the normal configuration for most sites and is not itself a weakness: rate limiting is usually enforced on authentication and API routes rather than the homepage, and most CDNs and load balancers throttle without advertising it. This is recorded so you can confirm that protection exists where it matters — it is not evidence that it is missing.",
      evidence: `GET ${targetUrl}\nNo rate-limit headers on this response (checked: X-RateLimit-Limit, RateLimit-Limit, Retry-After, and common CDN/WAF infrastructure signals)\nThis observes the homepage response only, and cannot show whether login or API routes are throttled.`,
      solution: "Confirm that rate limiting is enforced on login, registration, password reset and API endpoints — the routes that matter for brute force and credential stuffing. If it is already enforced at your CDN or load balancer, no change is needed. Returning X-RateLimit-Limit, X-RateLimit-Remaining and Retry-After makes the protection visible to clients and to scanners.",
      cweId: "CWE-307",
      cvssScore: 0,
      wstgId: "WSTG-ATHN-03",
    })];
  }

  return [];
}

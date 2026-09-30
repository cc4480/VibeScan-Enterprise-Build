import type { Category } from "./learn-types";
import { Shield, Lock, Code2 } from "lucide-react";

/** Learn-page categories: transport, injection and headers. */
export const LEARN_CATEGORIES_A: Category[] = [
  {
    id: "transport",
    label: "Transport Security",
    description: "Encryption, TLS configuration, and certificate checks that protect data in transit.",
    icon: Lock,
    checks: [
      {
        id: "https",
        title: "HTTPS / TLS Enforcement",
        shortTitle: "HTTPS",
        severity: "critical",
        cweId: "CWE-319",
        cvssScore: 9.1,
        owasp: "A02",
        wstgId: "WSTG-CRYP-01",
        what: "HTTPS (Hypertext Transfer Protocol Secure) encrypts all data sent between the user's browser and your server using TLS (Transport Layer Security). Without it, the connection is plaintext HTTP.",
        why: "On an unencrypted HTTP connection, anyone on the same network — a coffee shop Wi-Fi, an ISP, a government — can read or modify every byte of traffic. Passwords, session tokens, and personal data are fully exposed. This is the most critical security issue a web app can have.",
        howTested: "SecScan fetches your URL and inspects the protocol. If the final URL after redirects is HTTP, or if an HTTP version of your site exists and does not redirect to HTTPS, this finding is flagged as Critical.",
        fix: "Obtain a free TLS certificate from Let's Encrypt and configure your server to redirect all HTTP traffic to HTTPS. Then add HSTS to cache the preference.",
        fixCode: `# Nginx — redirect HTTP to HTTPS and enable TLS
server {
  listen 80;
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl;
  ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
  ssl_protocols       TLSv1.2 TLSv1.3;
  # ... rest of config
}`,
        fixCodeLang: "nginx",
        learnMore: "https://letsencrypt.org/getting-started/",
      },
      {
        id: "hsts",
        title: "HTTP Strict Transport Security (HSTS)",
        shortTitle: "HSTS",
        severity: "medium",
        cweId: "CWE-523",
        cvssScore: 5.3,
        owasp: "A05",
        wstgId: "WSTG-CONF-07",
        what: "HSTS is a response header that tells browsers to always connect to your site over HTTPS — never HTTP — for a specified duration. Once a browser sees this header, it will refuse to load your site over plaintext HTTP for the max-age period.",
        why: "Even if your server always redirects HTTP → HTTPS, a user's very first visit (or a visit after the HSTS cache expires) uses plain HTTP. An attacker performing an SSL stripping attack can intercept that initial HTTP request before the redirect happens. HSTS prevents this by pre-caching the HTTPS requirement.",
        howTested: "SecScan checks for the Strict-Transport-Security header on HTTPS responses. It flags absence as Medium severity, and flags max-age values under 180 days as Low.",
        fix: "Add the HSTS header to all HTTPS responses. For maximum protection, include includeSubDomains and preload, then register at hstspreload.org.",
        fixCode: `# Express (Node.js)
app.use((req, res, next) => {
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );
  next();
});

# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Vercel — vercel.json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [{ "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains; preload" }]
    }
  ]
}`,
        fixCodeLang: "javascript",
        learnMore: "https://hstspreload.org",
      },
    ],
  },
  {
    id: "injection",
    label: "Injection Defense",
    description: "Content Security Policy and XSS mitigations that block script injection attacks.",
    icon: Code2,
    checks: [
      {
        id: "csp-missing",
        title: "Missing Content-Security-Policy (CSP)",
        shortTitle: "CSP Missing",
        severity: "high",
        cweId: "CWE-79",
        cvssScore: 7.2,
        owasp: "A03",
        wstgId: "WSTG-CONF-12",
        what: "Content Security Policy is an HTTP header that tells the browser which sources of scripts, styles, images, and other resources are trusted. It is the primary browser-native defense against Cross-Site Scripting (XSS).",
        why: "Without a CSP, if an attacker achieves any form of HTML injection in your page, they can execute arbitrary JavaScript — stealing session cookies, impersonating the user, or exfiltrating data. CSP provides defense-in-depth even when XSS injection occurs.",
        howTested: "SecScan inspects the Content-Security-Policy header (and the meta http-equiv equivalent) on your main page response. Absence is flagged as High.",
        fix: "Add a strict CSP header. Start restrictive and loosen as needed using CSP violation reports.",
        fixCode: `# Start with this strict policy and tune with violation reports
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'

# Express (Node.js)
res.setHeader("Content-Security-Policy",
  "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
);

# Next.js — next.config.js
const securityHeaders = [
  { key: "Content-Security-Policy", value: "default-src 'self'; script-src 'self'; object-src 'none';" }
];`,
        fixCodeLang: "javascript",
        learnMore: "https://csp-evaluator.withgoogle.com",
      },
      {
        id: "csp-unsafe",
        title: "CSP Contains 'unsafe-inline' or 'unsafe-eval'",
        shortTitle: "CSP Unsafe Directives",
        severity: "medium",
        cweId: "CWE-79",
        cvssScore: 5.4,
        owasp: "A03",
        wstgId: "WSTG-CONF-12",
        what: "'unsafe-inline' allows inline <script> tags and event handlers to execute. 'unsafe-eval' allows eval(), setTimeout(string), and the Function() constructor. Both keywords defeat most of CSP's XSS protection.",
        why: "A CSP with 'unsafe-inline' still blocks some injections but is trivially bypassed once an attacker can inject a <script> tag or onclick handler. Most AI-generated React apps include 'unsafe-inline' in styles, which often bleeds into script policy.",
        howTested: "SecScan parses your CSP and flags any script-src or default-src directive that contains 'unsafe-inline' or 'unsafe-eval'.",
        fix: "Replace 'unsafe-inline' with nonces or hashes. For inline styles, consider moving them to external stylesheets.",
        fixCode: `# Instead of:
Content-Security-Policy: script-src 'self' 'unsafe-inline'

# Use nonces (server must generate a random nonce per request):
Content-Security-Policy: script-src 'self' 'nonce-{RANDOM_BASE64}'

# In your HTML:
<script nonce="{RANDOM_BASE64}">/* your inline script */</script>

# Or use hash-based approach (static scripts only):
Content-Security-Policy: script-src 'self' 'sha256-{BASE64_HASH_OF_SCRIPT}'`,
        fixCodeLang: "nginx",
      },
    ],
  },
  {
    id: "headers",
    label: "Security Headers",
    description: "Response headers that enable browser-level protections against common attacks.",
    icon: Shield,
    checks: [
      {
        id: "xframe",
        title: "Clickjacking Protection (X-Frame-Options)",
        shortTitle: "X-Frame-Options",
        severity: "medium",
        cweId: "CWE-1021",
        cvssScore: 4.3,
        owasp: "A05",
        wstgId: "WSTG-CLNT-09",
        what: "X-Frame-Options prevents your page from being embedded in an <iframe> on another site. The modern alternative is the CSP frame-ancestors directive, which offers more granular control.",
        why: "Clickjacking attacks trick users into clicking on elements they cannot see — your site is loaded invisibly in an iframe over a fake UI, and the user 'clicks' on your buttons without knowing. This is used to trigger account deletions, purchases, or OAuth approvals.",
        howTested: "SecScan checks for X-Frame-Options: DENY or SAMEORIGIN, and also for a frame-ancestors directive in the CSP header. Missing both is flagged as Medium.",
        fix: "Add X-Frame-Options: DENY (or SAMEORIGIN if you need same-domain embedding). For CSP-capable apps, prefer frame-ancestors.",
        fixCode: `# Simple — blocks all framing
X-Frame-Options: DENY

# Allow only same origin
X-Frame-Options: SAMEORIGIN

# Modern alternative via CSP (overrides X-Frame-Options in supporting browsers)
Content-Security-Policy: frame-ancestors 'none'

# Express
res.setHeader("X-Frame-Options", "DENY");`,
        fixCodeLang: "javascript",
      },
      {
        id: "xcto",
        title: "MIME Type Sniffing (X-Content-Type-Options)",
        shortTitle: "X-Content-Type-Options",
        severity: "medium",
        cweId: "CWE-16",
        cvssScore: 4.3,
        owasp: "A05",
        wstgId: "WSTG-CONF-07",
        what: "The X-Content-Type-Options: nosniff header stops browsers from guessing (sniffing) the MIME type of a response. Without it, a browser might execute a response it believes to be JavaScript even if it was served with a different content type.",
        why: "If an attacker uploads a file that contains JavaScript — such as a disguised image — and the server serves it with a loose content type, some browsers will sniff it as script and execute it. nosniff forces the browser to respect the declared content type.",
        howTested: "SecScan checks for X-Content-Type-Options: nosniff in response headers. Missing is flagged as Medium.",
        fix: "Add the header to all responses. It's a one-liner and has zero downside.",
        fixCode: `# Any web server — add to all responses
X-Content-Type-Options: nosniff

# Express
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

# Nginx
add_header X-Content-Type-Options "nosniff" always;`,
        fixCodeLang: "javascript",
      },
      {
        id: "referrer",
        title: "Referrer-Policy",
        shortTitle: "Referrer-Policy",
        severity: "low",
        cweId: "CWE-200",
        cvssScore: 3.1,
        owasp: "A05",
        wstgId: "WSTG-CONF-07",
        what: "The Referrer-Policy header controls how much information is included in the Referer header when a user navigates away from your page. Without it, full URLs (including paths, query strings, and tokens) can leak to third-party sites.",
        why: "If your app uses tokens or session IDs in query strings (common in password reset links or OAuth flows), the full URL can appear in third-party analytics, CDN logs, or tracking pixels — exposing sensitive values.",
        howTested: "SecScan checks for the Referrer-Policy header. Absence is flagged as Low.",
        fix: "Add strict-origin-when-cross-origin as a sensible default. Use no-referrer for maximum privacy.",
        fixCode: `Referrer-Policy: strict-origin-when-cross-origin

# Express
res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");`,
        fixCodeLang: "javascript",
      },
      {
        id: "permissions",
        title: "Permissions-Policy (Feature Policy)",
        shortTitle: "Permissions-Policy",
        severity: "low",
        cweId: "CWE-16",
        cvssScore: 2.4,
        owasp: "A05",
        wstgId: "WSTG-CONF-07",
        what: "Permissions-Policy (formerly Feature-Policy) is a header that lets you disable browser features your app doesn't use — like the camera, microphone, geolocation, and interest cohort APIs.",
        why: "If third-party scripts are ever injected into your page (via XSS or a compromised dependency), they could silently request device features. Restricting these at the header level prevents such API access regardless of what JavaScript runs.",
        howTested: "SecScan checks for the Permissions-Policy header. Absence is flagged as Low.",
        fix: "Disable any browser features you don't use. This is low-effort, high-value hardening.",
        fixCode: `Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=()

# Express
res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()");`,
        fixCodeLang: "javascript",
      },
    ],
  },
];

import { useState, useEffect, useRef } from "react";
import { Link } from "wouter";
import {
  Shield, ChevronRight, ExternalLink, AlertTriangle, Info, ArrowRight,
  ChevronDown, Lock, Code2, Globe, Cookie, Eye, Database, Wifi,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useSeo } from "@/lib/seo";

// ─── Data ────────────────────────────────────────────────────────────────────

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface Check {
  id: string;
  title: string;
  shortTitle: string;
  severity: Severity;
  cweId?: string;
  cvssScore?: number;
  owasp?: string;
  wstgId?: string;
  what: string;
  why: string;
  howTested: string;
  fix: string;
  fixCode?: string;
  fixCodeLang?: string;
  learnMore?: string;
}

interface Category {
  id: string;
  label: string;
  description: string;
  icon: React.ElementType;
  checks: Check[];
}

const CATEGORIES: Category[] = [
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
        howTested: "Seclayer fetches your URL and inspects the protocol. If the final URL after redirects is HTTP, or if an HTTP version of your site exists and does not redirect to HTTPS, this finding is flagged as Critical.",
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
        howTested: "Seclayer checks for the Strict-Transport-Security header on HTTPS responses. It flags absence as Medium severity, and flags max-age values under 180 days as Low.",
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
        howTested: "Seclayer inspects the Content-Security-Policy header (and the meta http-equiv equivalent) on your main page response. Absence is flagged as High.",
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
        howTested: "Seclayer parses your CSP and flags any script-src or default-src directive that contains 'unsafe-inline' or 'unsafe-eval'.",
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
        howTested: "Seclayer checks for X-Frame-Options: DENY or SAMEORIGIN, and also for a frame-ancestors directive in the CSP header. Missing both is flagged as Medium.",
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
        howTested: "Seclayer checks for X-Content-Type-Options: nosniff in response headers. Missing is flagged as Medium.",
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
        howTested: "Seclayer checks for the Referrer-Policy header. Absence is flagged as Low.",
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
        howTested: "Seclayer checks for the Permissions-Policy header. Absence is flagged as Low.",
        fix: "Disable any browser features you don't use. This is low-effort, high-value hardening.",
        fixCode: `Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=()

# Express
res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()");`,
        fixCodeLang: "javascript",
      },
    ],
  },
  {
    id: "cors",
    label: "CORS & Origin",
    description: "Cross-origin resource sharing policies that control which sites can access your API.",
    icon: Globe,
    checks: [
      {
        id: "cors-wildcard",
        title: "CORS Wildcard Origin (Access-Control-Allow-Origin: *)",
        shortTitle: "CORS Wildcard",
        severity: "medium",
        cweId: "CWE-942",
        cvssScore: 6.5,
        owasp: "A05",
        wstgId: "WSTG-CONF-07",
        what: "CORS (Cross-Origin Resource Sharing) headers control which external websites can make browser-side API requests to your server. Access-Control-Allow-Origin: * allows any website in the world to call your API from a user's browser.",
        why: "A wildcard CORS policy combined with cookies or Authorization headers is particularly dangerous — it allows any malicious website a user visits to make authenticated API requests on their behalf. Even without credentials, wildcard CORS on user-data endpoints can enable cross-site data theft.",
        howTested: "Seclayer sends an OPTIONS preflight request from a probe origin and inspects the Access-Control-Allow-Origin response. A wildcard on endpoints that serve user-specific data is flagged as Medium.",
        fix: "Replace the wildcard with an explicit allowlist of your trusted frontend origins.",
        fixCode: `# Instead of:
Access-Control-Allow-Origin: *

# Use an explicit allowlist:
Access-Control-Allow-Origin: https://app.yourdomain.com

# Express — check origin against allowlist
const ALLOWED_ORIGINS = ["https://app.yourdomain.com", "https://yourdomain.com"];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) cb(null, true);
    else cb(new Error("Not allowed by CORS"));
  },
  credentials: true,
}));`,
        fixCodeLang: "javascript",
      },
    ],
  },
  {
    id: "cookies",
    label: "Cookies & Sessions",
    description: "Cookie attribute checks that protect session tokens from theft and CSRF.",
    icon: Cookie,
    checks: [
      {
        id: "cookie-secure",
        title: "Cookie Missing Secure Flag",
        shortTitle: "Cookie: Secure Flag",
        severity: "high",
        cweId: "CWE-614",
        cvssScore: 6.5,
        owasp: "A02",
        wstgId: "WSTG-SESS-02",
        what: "The Secure attribute on a cookie tells the browser to only send it over HTTPS connections — never over plain HTTP. Without it, the cookie can be transmitted in cleartext if the user ever visits an HTTP version of your site.",
        why: "Session tokens sent over HTTP are visible to any network observer. Even if your main site redirects to HTTPS, an active attacker can intercept the HTTP request before the redirect happens (SSL stripping), capturing the session cookie in cleartext.",
        howTested: "Seclayer inspects all Set-Cookie headers and flags any cookie that lacks the Secure attribute.",
        fix: "Add Secure to all cookie definitions. Pair it with HttpOnly and SameSite for full protection.",
        fixCode: `# Full secure cookie
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/

# Express (express-session)
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,   // only send over HTTPS
    httpOnly: true, // no JS access
    sameSite: "lax" // CSRF protection
  }
}));`,
        fixCodeLang: "javascript",
      },
      {
        id: "cookie-httponly",
        title: "Cookie Missing HttpOnly Flag",
        shortTitle: "Cookie: HttpOnly Flag",
        severity: "medium",
        cweId: "CWE-1004",
        cvssScore: 5.3,
        owasp: "A07",
        wstgId: "WSTG-SESS-02",
        what: "The HttpOnly attribute prevents client-side JavaScript from accessing a cookie via document.cookie. This is the primary mitigation against session theft via XSS.",
        why: "If an attacker successfully injects JavaScript into your page (via XSS), they can read all non-HttpOnly cookies with document.cookie. This is how session hijacking works in practice — the attacker exfiltrates the session token and logs in as the victim.",
        howTested: "Seclayer inspects all Set-Cookie headers for the HttpOnly attribute. Session cookies without it are flagged as Medium.",
        fix: "Add HttpOnly to all session and authentication cookies.",
        fixCode: `Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax

# Note: cookies used by client-side JS (e.g. CSRF tokens read by fetch())
# legitimately omit HttpOnly — only session tokens need it.`,
        fixCodeLang: "nginx",
      },
      {
        id: "cookie-samesite",
        title: "Cookie Missing SameSite Attribute",
        shortTitle: "Cookie: SameSite",
        severity: "medium",
        cweId: "CWE-352",
        cvssScore: 4.3,
        owasp: "A01",
        wstgId: "WSTG-SESS-02",
        what: "SameSite controls whether a cookie is sent with cross-site requests (from other domains). SameSite=Strict never sends on cross-site requests. SameSite=Lax sends on top-level navigations (following links) but not on fetch/XHR requests. SameSite=None allows all cross-site requests.",
        why: "Without SameSite, cookies are sent with every cross-site request — including form submissions and iframes from malicious sites. This enables Cross-Site Request Forgery (CSRF) attacks where a victim visits an attacker's site and their browser silently submits a request to your app with their session.",
        howTested: "Seclayer checks all Set-Cookie headers for the SameSite attribute. Absence is flagged as Medium.",
        fix: "Add SameSite=Lax as the default. Use Strict for highly sensitive cookies. Only use None for third-party integrations (requires Secure).",
        fixCode: `# Safe default for most apps
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax

# Maximum protection
Set-Cookie: admin_session=xyz; Secure; HttpOnly; SameSite=Strict

# Third-party (embeds, iframes) — requires Secure
Set-Cookie: embed_token=abc; Secure; SameSite=None`,
        fixCodeLang: "nginx",
      },
    ],
  },
  {
    id: "disclosure",
    label: "Information Disclosure",
    description: "Exposed files, server banners, and debug pages that hand attackers a roadmap.",
    icon: Eye,
    checks: [
      {
        id: "server-header",
        title: "Server Version Disclosure",
        shortTitle: "Server Header",
        severity: "info",
        cweId: "CWE-200",
        owasp: "A05",
        wstgId: "WSTG-INFO-02",
        what: "Many web servers and frameworks include version information in the Server response header (e.g., nginx/1.18.0, Apache/2.4.51 (Ubuntu)). This is also sometimes seen in the X-Powered-By header for application frameworks.",
        why: "Version disclosure alone is not exploitable, but it hands attackers a roadmap. Knowing you run nginx/1.18.0 lets them look up the CVE list for exactly that version and craft targeted exploits. Removing version numbers is simple defense-in-depth.",
        howTested: "Seclayer reads the Server header and checks for version numbers using a regex. Disclosure is flagged as Info.",
        fix: "Configure your server to omit version numbers from headers.",
        fixCode: `# Nginx — nginx.conf
http {
  server_tokens off; # Hides version from Server header and error pages
}

# Apache — httpd.conf
ServerTokens Prod     # Shows only "Apache"
ServerSignature Off   # Removes version from error pages

# Express — remove X-Powered-By
app.disable("x-powered-by");
# Or use helmet which handles this automatically:
app.use(helmet());`,
        fixCodeLang: "nginx",
      },
      {
        id: "env-exposure",
        title: "Exposed .env or Config Files",
        shortTitle: ".env Exposure",
        severity: "critical",
        cweId: "CWE-312",
        cvssScore: 9.8,
        owasp: "A02",
        wstgId: "WSTG-CONF-05",
        what: "Environment files like .env, .env.local, .env.production, or configuration files like wp-config.php contain database credentials, API keys, and other secrets. If accessible over HTTP, the entire application is compromised.",
        why: "A single exposed .env file typically reveals database URLs (direct DB access), secret keys (JWT forgery, session tampering), payment API keys (financial fraud), and third-party API credentials. This is one of the most common and catastrophic misconfigurations in deployed applications.",
        howTested: "Seclayer probes common paths like /.env, /.env.local, /.env.production, /wp-config.php, /config.php and checks if they return accessible content (200 status with readable text).",
        fix: "Block .env files at the web server level. Never place them in the web root.",
        fixCode: `# Nginx — block .env files
location ~ /\\.env {
  deny all;
  return 404;
}

# Apache — .htaccess
<FilesMatch "^\\.env">
  Require all denied
</FilesMatch>

# Vercel — never exposes .env files (handled by the platform)
# But ensure secrets are in Environment Variables, not committed files.

# Add to .gitignore AND verify your deploy doesn't copy them:
.env
.env.local
.env.production`,
        fixCodeLang: "nginx",
      },
      {
        id: "git-exposure",
        title: "Exposed .git Directory",
        shortTitle: ".git Directory",
        severity: "critical",
        cweId: "CWE-538",
        cvssScore: 9.8,
        owasp: "A05",
        wstgId: "WSTG-CONF-05",
        what: "If the .git directory is accessible from the web, attackers can reconstruct your entire source code — including all commit history, secret files, and any credentials that were ever committed, even if later removed.",
        why: "Full source code disclosure allows attackers to audit your entire application for vulnerabilities at their leisure, find hardcoded secrets in any commit, identify all API endpoints, understand your authentication logic, and craft precise exploits.",
        howTested: "Seclayer requests /.git/HEAD and /.git/config and checks if they return a 200 response with git-formatted content.",
        fix: "Block the .git directory at the web server level. Never deploy the .git folder to a public server.",
        fixCode: `# Nginx
location ~ /\\.git {
  deny all;
  return 404;
}

# Apache
<DirectoryMatch "^\\.git">
  Require all denied
</DirectoryMatch>

# Better yet — exclude .git from your deployment
# Most CI/CD pipelines (Vercel, Netlify, Railway) don't expose .git
# If self-hosting, use rsync --exclude='.git' or check your Dockerfile`,
        fixCodeLang: "nginx",
      },
      {
        id: "swagger-exposure",
        title: "API Documentation Exposed (Swagger / OpenAPI)",
        shortTitle: "API Docs Exposure",
        severity: "medium",
        cweId: "CWE-200",
        cvssScore: 5.3,
        owasp: "A05",
        wstgId: "WSTG-CONF-05",
        what: "Swagger UI, OpenAPI JSON, and similar API documentation endpoints describe every route, parameter, request format, and authentication method of your API. Leaving them publicly accessible makes your API an open book for attackers.",
        why: "API docs reduce the effort required to attack your API from hours of enumeration to seconds of reading. Attackers can see every endpoint, understand expected inputs, find undocumented admin routes, and craft precise injection or authentication bypass attempts.",
        howTested: "Seclayer probes common paths including /swagger.json, /swagger-ui.html, /api-docs, /openapi.json, /api/v1/docs, and similar patterns.",
        fix: "Require authentication to access API docs in production, or serve docs only on internal networks.",
        fixCode: `# Express — protect swagger routes with auth middleware
app.use("/api-docs", requireAuth, swaggerUi.serve);
app.get("/api-docs", requireAuth, swaggerUi.setup(swaggerDocument));

# Or disable entirely in production
if (process.env.NODE_ENV !== "production") {
  app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(spec));
}`,
        fixCodeLang: "javascript",
      },
    ],
  },
  {
    id: "supabase",
    label: "Supabase & BaaS",
    description: "Supabase RLS, Firebase rules, PocketBase, and Appwrite access control checks.",
    icon: Database,
    checks: [
      {
        id: "supabase-rls",
        title: "Supabase Row Level Security (RLS) Not Enabled",
        shortTitle: "Supabase RLS",
        severity: "critical",
        cweId: "CWE-284",
        cvssScore: 9.8,
        owasp: "A01",
        what: "Supabase provides a public JavaScript client that connects directly to your PostgreSQL database. Row Level Security (RLS) is PostgreSQL's built-in mechanism for restricting which rows a user can read, insert, update, or delete based on security policies.",
        why: "If RLS is not enabled on a Supabase table, any user with your anon key (which is public by default — embedded in your frontend) can query the entire table with no restrictions. In many vibe-coded apps, this means any visitor can read all user data, all records, and potentially delete or modify them. This is arguably the most common critical vulnerability in AI-generated Supabase apps.",
        howTested: "Seclayer extracts the Supabase project URL from your app's JavaScript, then makes an unauthenticated REST API request to known table endpoints. If the response returns rows with HTTP 200, RLS is not enabled on those tables. This is the same request an attacker would make.",
        fix: "Enable RLS on every Supabase table and write policies that restrict access to the authenticated user's own rows.",
        fixCode: `-- Step 1: Enable RLS on each table (run in Supabase SQL editor)
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
-- Repeat for every table

-- Step 2: Create policies that match your access rules

-- Allow users to read only their own profile
CREATE POLICY "Users can view own profile"
ON profiles FOR SELECT
USING (auth.uid() = user_id);

-- Allow users to update only their own profile
CREATE POLICY "Users can update own profile"
ON profiles FOR UPDATE
USING (auth.uid() = user_id);

-- Allow public read of published posts
CREATE POLICY "Anyone can read published posts"
ON posts FOR SELECT
USING (published = true);

-- Allow authors to manage their own posts
CREATE POLICY "Authors can manage own posts"
ON posts FOR ALL
USING (auth.uid() = author_id);`,
        fixCodeLang: "sql",
        learnMore: "https://supabase.com/docs/guides/database/postgres/row-level-security",
      },
    ],
  },
  {
    id: "network",
    label: "Network & DNS",
    description: "Email security records, DNS configuration, and exposed network services.",
    icon: Wifi,
    checks: [
      {
        id: "spf",
        title: "Missing or Weak SPF Record",
        shortTitle: "SPF Record",
        severity: "high",
        cweId: "CWE-345",
        cvssScore: 7.5,
        owasp: "A05",
        what: "SPF (Sender Policy Framework) is a DNS TXT record that lists which mail servers are authorised to send email on behalf of your domain. Receiving mail servers check SPF to detect forged sender addresses.",
        why: "Without SPF, anyone can send email that appears to come from your domain — enabling phishing campaigns, business email compromise, and spam. Attackers craft convincing emails with your domain as the sender to trick recipients into revealing credentials or authorising payments.",
        howTested: "Seclayer queries the DNS TXT record for your apex domain via Cloudflare DoH. Missing SPF is flagged High. Permissive +all (allows all senders) is flagged Critical.",
        fix: "Publish an SPF record that lists your authorised sending sources and ends with -all to reject unauthorised senders.",
        fixCode: `# Add a TXT record to your DNS — example for Google Workspace + SendGrid:
v=spf1 include:_spf.google.com include:sendgrid.net -all

# Breaking it down:
# v=spf1              — SPF version
# include:_spf.google.com — authorise Google's mail servers
# include:sendgrid.net    — authorise SendGrid
# -all                    — REJECT all other senders (hard fail)
# ~all                    — SOFT FAIL others (less strict, still common)

# Check your record with:
dig TXT yourdomain.com | grep spf`,
        fixCodeLang: "nginx",
        learnMore: "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
      },
      {
        id: "dmarc",
        title: "Missing or Weak DMARC Policy",
        shortTitle: "DMARC Policy",
        severity: "high",
        cweId: "CWE-345",
        cvssScore: 7.5,
        owasp: "A05",
        what: "DMARC (Domain-based Message Authentication, Reporting & Conformance) builds on SPF and DKIM to tell receiving mail servers what to do with messages that fail authentication — reject, quarantine, or do nothing.",
        why: "SPF and DKIM alone don't prevent spoofing of the human-visible From address. DMARC ties the SPF/DKIM results to the header From domain and specifies enforcement. Without DMARC, authenticated SPF/DKIM emails can still be spoofed at the UI level.",
        howTested: "Seclayer queries _dmarc.yourdomain.com via DNS. Missing DMARC is High. p=none (monitoring only, no enforcement) is Medium.",
        fix: "Publish a DMARC record and gradually move to p=reject after monitoring with aggregate reports.",
        fixCode: `# Add TXT record at _dmarc.yourdomain.com

# Start with monitoring (p=none) to see who's sending on your behalf:
v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com

# After reviewing reports, tighten to quarantine:
v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com; pct=100

# Full enforcement — reject all failing messages:
v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; adkim=s; aspf=s`,
        fixCodeLang: "nginx",
        learnMore: "https://dmarc.org/overview/",
      },
    ],
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

const SEV_CONFIG: Record<Severity, { label: string; bg: string; text: string; border: string; dot: string; pill: string }> = {
  critical: { label: "Critical", bg: "bg-red-500/10",    text: "text-red-400",    border: "border-red-500/30",    dot: "bg-red-500",    pill: "bg-red-500/15 text-red-400 border-red-500/30" },
  high:     { label: "High",     bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30", dot: "bg-orange-500", pill: "bg-orange-500/15 text-orange-400 border-orange-500/30" },
  medium:   { label: "Medium",   bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/30", dot: "bg-yellow-500", pill: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" },
  low:      { label: "Low",      bg: "bg-blue-500/10",   text: "text-blue-400",   border: "border-blue-500/30",   dot: "bg-blue-500",   pill: "bg-blue-500/15 text-blue-400 border-blue-500/30" },
  info:     { label: "Info",     bg: "bg-slate-500/10",  text: "text-slate-400",  border: "border-slate-500/30",  dot: "bg-slate-400",  pill: "bg-slate-500/15 text-slate-400 border-slate-500/30" },
};

function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg = SEV_CONFIG[severity];
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border", cfg.pill)}>
      <span className={cn("w-1.5 h-1.5 rounded-full", cfg.dot)} />
      {cfg.label}
    </span>
  );
}

function CodeBlock({ code, lang }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <div className="relative mt-3">
      <div className="flex items-center justify-between bg-slate-900 border border-white/10 rounded-t-lg px-4 py-2">
        <span className="text-xs text-slate-500 font-mono">{lang ?? "code"}</span>
        <button onClick={copy} className="text-xs text-slate-500 hover:text-slate-300 transition-colors">
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
      <pre className="bg-slate-950 border border-t-0 border-white/10 rounded-b-lg p-4 overflow-x-auto text-sm text-slate-300 leading-relaxed font-mono">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function CheckAccordion({ check }: { check: Check }) {
  const [open, setOpen] = useState(false);
  const cfg = SEV_CONFIG[check.severity];

  return (
    <div className={cn(
      "rounded-xl border transition-colors duration-200",
      open ? "border-white/10 bg-white/[0.03]" : "border-white/5 bg-white/[0.01] hover:border-white/10 hover:bg-white/[0.02]"
    )}>
      {/* Row header — always visible */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left"
      >
        <span className={cn("w-2 h-2 rounded-full shrink-0", cfg.dot)} />
        <span className="flex-1 font-medium text-foreground text-sm">{check.title}</span>
        <div className="flex items-center gap-3 shrink-0">
          <SeverityBadge severity={check.severity} />
          {check.cweId && (
            <span className="hidden sm:block text-xs text-muted-foreground font-mono">{check.cweId}</span>
          )}
          {check.cvssScore !== undefined && (
            <span className="hidden md:block text-xs text-muted-foreground font-mono">
              CVSS {check.cvssScore.toFixed(1)}
            </span>
          )}
          <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform duration-200", open && "rotate-180")} />
        </div>
      </button>

      {/* Expanded content */}
      {open && (
        <div className="px-5 pb-6 border-t border-white/5 mt-0 pt-5 space-y-5">
          {/* Meta badges */}
          <div className="flex flex-wrap gap-2">
            {check.owasp && (
              <span className="px-2.5 py-1 rounded-full bg-primary/10 border border-primary/20 text-xs text-primary font-semibold font-mono">
                OWASP {check.owasp}
              </span>
            )}
            {check.cweId && (
              <a
                href={`https://cwe.mitre.org/data/definitions/${check.cweId.replace("CWE-", "")}.html`}
                target="_blank" rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-muted-foreground hover:text-foreground transition-colors font-mono"
              >
                {check.cweId} <ExternalLink className="w-2.5 h-2.5" />
              </a>
            )}
            {check.wstgId && (
              <span className="px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-muted-foreground font-mono">
                {check.wstgId}
              </span>
            )}
          </div>

          {/* What it is */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/60 mb-2">What it is</p>
            <p className="text-sm text-muted-foreground leading-relaxed">{check.what}</p>
          </div>

          {/* Why it matters */}
          <div className="flex gap-3 p-4 rounded-xl bg-orange-500/5 border border-orange-500/20">
            <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-orange-400/70 mb-1">Why it matters</p>
              <p className="text-sm text-muted-foreground leading-relaxed">{check.why}</p>
            </div>
          </div>

          {/* How tested */}
          <div className="flex gap-3 p-4 rounded-xl bg-primary/5 border border-primary/20">
            <Shield className="w-4 h-4 text-primary shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-primary/70 mb-1">How Seclayer tests this</p>
              <p className="text-sm text-muted-foreground leading-relaxed">{check.howTested}</p>
            </div>
          </div>

          {/* Fix */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/60 mb-2">How to fix it</p>
            <p className="text-sm text-muted-foreground leading-relaxed mb-1">{check.fix}</p>
            {check.fixCode && <CodeBlock code={check.fixCode} lang={check.fixCodeLang} />}
          </div>

          {check.learnMore && (
            <a
              href={check.learnMore} target="_blank" rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
            >
              <Info className="w-3.5 h-3.5" /> Learn more <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function LearnPage() {
  useSeo({
    title: "Security Documentation — Seclayer",
    description: "Plain-English explanations of every security check Seclayer runs: HTTPS, HSTS, CSP, X-Frame-Options, CORS, cookie flags, Supabase RLS, and more. With code fixes.",
    canonical: "https://seclayer.io/learn",
  });

  const [activeCategory, setActiveCategory] = useState(CATEGORIES[0].id);
  const tabsRef = useRef<HTMLDivElement>(null);

  const currentCategory = CATEGORIES.find((c) => c.id === activeCategory) ?? CATEGORIES[0];
  const CategoryIcon = currentCategory.icon;

  const allChecks = CATEGORIES.flatMap((c) => c.checks);
  const totalChecks = allChecks.length;
  const criticalCount = allChecks.filter((c) => c.severity === "critical").length;

  // Scroll active tab into view on mobile
  useEffect(() => {
    const el = tabsRef.current?.querySelector(`[data-cat="${activeCategory}"]`) as HTMLElement | null;
    el?.scrollIntoView({ inline: "center", block: "nearest", behavior: "smooth" });
  }, [activeCategory]);

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 pb-24">

      {/* Page header */}
      <div className="pt-4 pb-10 max-w-2xl">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-semibold mb-6 uppercase tracking-wider">
          <Shield className="w-3.5 h-3.5" /> Security Reference
        </div>
        <h1 className="text-4xl md:text-5xl font-bold mb-4 tracking-tight">
          Security checks documentation
        </h1>
        <p className="text-lg text-muted-foreground mb-5">
          Plain-English explanations of every vulnerability Seclayer detects — what it is, why attackers exploit it, how we test for it, and exactly how to fix it.
        </p>
        <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-primary" />{totalChecks} checks documented</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500" />{criticalCount} critical severity</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-slate-400" />OWASP Top 10 mapped</span>
        </div>
      </div>

      {/* Category tabs */}
      <div
        ref={tabsRef}
        className="flex gap-1 overflow-x-auto pb-px mb-8 scrollbar-none border-b border-white/5"
        style={{ scrollbarWidth: "none" }}
      >
        {CATEGORIES.map((cat) => {
          const Icon = cat.icon;
          const isActive = cat.id === activeCategory;
          const critCount = cat.checks.filter((c) => c.severity === "critical").length;
          return (
            <button
              key={cat.id}
              data-cat={cat.id}
              onClick={() => setActiveCategory(cat.id)}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-lg whitespace-nowrap transition-all duration-150 border-b-2 -mb-px",
                isActive
                  ? "text-primary border-primary bg-primary/5"
                  : "text-muted-foreground border-transparent hover:text-foreground hover:bg-white/5"
              )}
            >
              <Icon className="w-3.5 h-3.5 shrink-0" />
              {cat.label}
              {critCount > 0 && (
                <span className="ml-0.5 px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 text-xs font-bold leading-none">
                  {critCount}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Active category panel */}
      <div className="space-y-6">
        {/* Category header */}
        <div className="flex items-start gap-4 p-5 rounded-xl bg-white/[0.03] border border-white/8">
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
            <CategoryIcon className="w-5 h-5 text-primary" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-3 mb-1">
              <h2 className="text-lg font-bold text-foreground">{currentCategory.label}</h2>
              <span className="px-2 py-0.5 rounded-full bg-white/5 border border-white/10 text-xs text-muted-foreground font-mono">
                {currentCategory.checks.length} {currentCategory.checks.length === 1 ? "check" : "checks"}
              </span>
            </div>
            <p className="text-sm text-muted-foreground">{currentCategory.description}</p>
          </div>
        </div>

        {/* Severity legend */}
        <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
          <span className="font-medium text-muted-foreground/60 mr-1">Severity:</span>
          {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => {
            const count = currentCategory.checks.filter((c) => c.severity === s).length;
            if (count === 0) return null;
            const cfg = SEV_CONFIG[s];
            return (
              <span key={s} className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border", cfg.pill)}>
                <span className={cn("w-1.5 h-1.5 rounded-full", cfg.dot)} />
                {cfg.label} ({count})
              </span>
            );
          })}
        </div>

        {/* Accordion list */}
        <div className="space-y-2">
          {currentCategory.checks.map((check) => (
            <CheckAccordion key={check.id} check={check} />
          ))}
        </div>

        {/* Category nav footer */}
        <div className="flex items-center justify-between pt-4 border-t border-white/5">
          <button
            onClick={() => {
              const idx = CATEGORIES.findIndex((c) => c.id === activeCategory);
              if (idx > 0) setActiveCategory(CATEGORIES[idx - 1].id);
            }}
            disabled={activeCategory === CATEGORIES[0].id}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            ← Previous
          </button>
          <span className="text-xs text-muted-foreground">
            {CATEGORIES.findIndex((c) => c.id === activeCategory) + 1} / {CATEGORIES.length}
          </span>
          <button
            onClick={() => {
              const idx = CATEGORIES.findIndex((c) => c.id === activeCategory);
              if (idx < CATEGORIES.length - 1) setActiveCategory(CATEGORIES[idx + 1].id);
            }}
            disabled={activeCategory === CATEGORIES[CATEGORIES.length - 1].id}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            Next →
          </button>
        </div>
      </div>

      {/* Footer CTA */}
      <div className="mt-12 glass-card rounded-2xl p-8 text-center border border-primary/20 bg-primary/5">
        <Shield className="w-10 h-10 text-primary mx-auto mb-4" />
        <h2 className="text-2xl font-bold mb-2">See how your app scores</h2>
        <p className="text-muted-foreground mb-6 max-w-md mx-auto">
          Seclayer tests all of the above — plus dozens more checks — in a single automated scan. Get your grade in under 10 minutes.
        </p>
        <Link href="/scan"
          className="inline-flex items-center gap-2 px-8 py-3 bg-primary text-primary-foreground font-bold rounded-xl hover:shadow-[0_0_20px_rgba(20,184,120,0.4)] hover:-translate-y-0.5 transition-all duration-200">
          Scan your app <ArrowRight className="w-4 h-4" />
        </Link>
      </div>
    </div>
  );
}

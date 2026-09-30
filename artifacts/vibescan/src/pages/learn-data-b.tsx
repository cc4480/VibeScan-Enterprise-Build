import type { Category } from "./learn-types";
import { Info, Globe, Cookie, Eye } from "lucide-react";

/** Learn-page categories: CORS, cookies and disclosure. */
export const LEARN_CATEGORIES_B: Category[] = [
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
        howTested: "SecScan sends an OPTIONS preflight request from a probe origin and inspects the Access-Control-Allow-Origin response. A wildcard on endpoints that serve user-specific data is flagged as Medium.",
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
        howTested: "SecScan inspects all Set-Cookie headers and flags any cookie that lacks the Secure attribute.",
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
        howTested: "SecScan inspects all Set-Cookie headers for the HttpOnly attribute. Session cookies without it are flagged as Medium.",
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
        howTested: "SecScan checks all Set-Cookie headers for the SameSite attribute. Absence is flagged as Medium.",
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
        howTested: "SecScan reads the Server header and checks for version numbers using a regex. Disclosure is flagged as Info.",
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
        howTested: "SecScan probes common paths like /.env, /.env.local, /.env.production, /wp-config.php, /config.php and checks if they return accessible content (200 status with readable text).",
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
        howTested: "SecScan requests /.git/HEAD and /.git/config and checks if they return a 200 response with git-formatted content.",
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
        howTested: "SecScan probes common paths including /swagger.json, /swagger-ui.html, /api-docs, /openapi.json, /api/v1/docs, and similar patterns.",
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
];

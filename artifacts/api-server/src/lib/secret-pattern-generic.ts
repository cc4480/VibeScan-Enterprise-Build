import { isRealSecretValue, looksLikeInterfaceText } from "./secret-pattern-filters";
import type { SecretPattern } from "./secret-pattern-data";
import { shannonEntropy, looksLikeAName, looksLikeReference, isTrivialPassword, isLocalHost, isPlaceholderToken } from "./secretPlaceholders";
import { isPublicByDesignValue, isPublicByDesignName } from "./publicKeys";
import { JWT_PATTERNS } from "./secret-pattern-jwt";
import { AI_VENDOR_PATTERNS } from "./secret-pattern-ai";

/** Generic secret patterns: JWTs, keys and passwords by name, internal hosts, env-var leaks, connection URLs, AI vendors. */
export const GENERIC_SECRET_PATTERNS: SecretPattern[] = [
  ...JWT_PATTERNS,

  // ── Generic Secrets ───────────────────────────────────────────────────────
  {
    name: "Hardcoded Password in Source Code",
    firstPartyOnly: true,
    // Excludes HTML attribute contexts (placeholder="", type="password") and
    // JSON schema / documentation patterns (description, label, hint).
    pattern: /(?:^|[,{;\n])\s*(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/im,
    severity: "high", cvssScore: 7.5, cweId: "CWE-259",
    description: "A hardcoded password was found in client-side JavaScript source code. Hardcoded credentials are accessible to anyone who views the source, persist forever unless code is redeployed, and cannot be rotated without a new deployment.",
    solution: "Remove all hardcoded credentials. Use environment variables on the server side. For client-side authentication, let users provide their own credentials — never hardcode service accounts in frontend code.",
    validate: (m) => {
      // Exclude obvious HTML attributes and placeholder/example strings
      if (/placeholder|type\s*=\s*["']password|label|description|hint/i.test(m)) return false;
      if (/["'](password|passwd|admin|test|secret|changeme|letmein|abc123|hunter2|qwerty|pass|1234|0000|blank|empty|null|undefined)["']/i.test(m)) return false;
      // Extract the value and check it's not a placeholder
      const valMatch = /[:=]\s*["']([^"']+)["']/.exec(m);
      if (!valMatch) return false;
      const val = valMatch[1];
      if (/EXAMPLE|PLACEHOLDER|YOUR_|<|>|\*{3,}|\.{3,}|xxx|yyy|zzz/i.test(val)) return false;
      if (looksLikeInterfaceText(val)) return false;
      // Require reasonable entropy — real passwords aren't all-same-char repeating strings
      return shannonEntropy(val) >= 2.5;
    },
  },
  // A secret and an api key are not the same claim, and were being reported as
  // one. `secret`, `auth_token` and `access_token` in browser-delivered code
  // name something that was never meant to leave the server. `apiKey` names the
  // thing a client-side SDK is *supposed* to ship: Coveo, Algolia, Mapbox,
  // Segment and Sentry all hand the browser one, and so does Google, whose AIza
  // key this file already reports at Info for exactly this reason.
  //
  // zoom.us was reported Medium for `apiKey` inside window.__zoomCoveoConfig —
  // a search widget's key, public by construction. Whether such a key is
  // properly restricted cannot be determined from the page, so the honest
  // finding is "verify this", not "you leaked a secret".
  {
    name: "Hardcoded Secret or Auth Token in Source",
    firstPartyOnly: true,
    pattern: /(?:secret|auth_token|access_token)\s*[:=]\s*["']([a-zA-Z0-9\-_+/]{16,})["']/i,
    severity: "medium", cvssScore: 6.5, cweId: "CWE-798",
    description: "A hardcoded secret or authentication token was found in client-side JavaScript. Unlike a publishable API key, a value named as a secret or an auth token is not meant to reach the browser at all — anyone who visits the site can read it.",
    solution: "Move the secret to the backend. Use short-lived, scoped tokens issued by your backend for any client-side API calls, and rotate the value that was exposed.",
    validate: (m) => isRealSecretValue(m),
  },
  {
    name: "API Key in Client Code (verify restrictions)",
    firstPartyOnly: true,
    pattern: /(?:api_key|apikey)\s*[:=]\s*["']([a-zA-Z0-9\-_+/]{16,})["']/i,
    severity: "info", cvssScore: 0, cweId: "CWE-798",
    description: "An API key was found in client-side JavaScript. Client-side SDKs — search, maps, analytics, error reporting — are designed to ship a key to the browser, so its presence is expected rather than a leak. The risk is a key left without origin, referrer or scope restrictions, which cannot be determined from the page. This is a prompt to verify, not a confirmed exposure.",
    solution: "Confirm with the vendor's console that this key is restricted to your origins and to the minimum scope it needs — for search SDKs, a search-only key that cannot write. If it turns out to be a privileged or server-side key, rotate it and move it behind your backend.",
    validate: (m) => isRealSecretValue(m),
  },

  // ── Internal infrastructure ───────────────────────────────────────────────
  {
    name: "Internal IP Address Exposed",
    // Require code-like context — IP must appear after an assignment/string delimiter,
    // not as a lone number that happens to look like an RFC-1918 address.
    pattern: /(?:["'`]|host\s*[:=]\s*["'`]?|url\s*[:=]\s*["'`]?|endpoint\s*[:=]\s*["'`]?|server\s*[:=]\s*["'`]?)\s*((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\.\d{1,3})/,
    severity: "low", cvssScore: 3.1, cweId: "CWE-200",
    description: "An internal/private IP address was found referenced in JavaScript source code in a configuration context. This reveals internal network topology, making lateral movement easier if an attacker gains any foothold.",
    solution: "Remove internal IP references from client-side code. Replace hardcoded IPs with environment-variable-driven configuration on the server side. Review your build process to ensure internal infrastructure details don't leak into production bundles.",
    validate: (m, before = "") => {
      // Skip clearly benign/example contexts. The match is only the quote and the address, so what
      // says "example" is the field name just before it (`example:"10.1.2.80"` in a library's metadata).
      if (/\b(?:examples?|samples?|demo|placeholder|e\.g\.?|eg)\W{0,3}$/i.test(before)) return false;
      if (/example|sample|demo|placeholder|comment|doc|test/i.test(m)) return false;
      if (/192\.168\.1\.(1|0|255)\b/.test(m) && /(?:gateway|router|default)/i.test(m)) return false;
      return true;
    },
  },

  ...AI_VENDOR_PATTERNS,

  // ── Vite / Create React App / Next.js env var leaks ──────────────────────
  {
    // Vite inlines VITE_* vars, CRA inlines REACT_APP_*, Next.js inlines NEXT_PUBLIC_*
    // into the production bundle — making them publicly visible in page source.
    // This is the #1 security mistake in vibe-coded apps.
    name: "Secret Environment Variable Leaked in Frontend Bundle",
    pattern: /["'`]((?:VITE|REACT_APP|NEXT_PUBLIC)_[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASS(?:WORD)?|API|AUTH|PRIVATE|CREDENTIAL)[A-Z0-9_]*)["'`]\s*:\s*["'`]([^"'`\s]{10,})["'`]/,
    severity: "critical", cvssScore: 9.5, cweId: "CWE-312",
    description: "A secret-sounding environment variable was found baked into the frontend JavaScript bundle. Build tools (Vite, Create React App, Next.js) automatically inline env vars prefixed with VITE_/REACT_APP_/NEXT_PUBLIC_ into the production bundle — making them publicly readable by anyone who inspects the page source. This is the #1 security mistake in vibe-coded apps.",
    solution: "IMMEDIATELY: Remove this variable from your .env file and revoke/rotate any exposed secrets. GOING FORWARD: Only prefix env vars with VITE_/REACT_APP_/NEXT_PUBLIC_ if they are safe to be fully public (like a Stripe publishable key or Firebase project ID). Move ALL secret keys to a backend API route — the key lives in a server-side .env file, the frontend calls /api/your-endpoint, and the actual secret never reaches the browser.",
    validate: (m) => {
      const valMatch = /:\s*["'`]([^"'`\s]+)["'`]/.exec(m);
      if (!valMatch) return false;
      const val = valMatch[1] ?? "";
      // A key the vendor publishes for the browser is what these prefixes are FOR (Stripe pk_live_,
      // Supabase anon, Firebase AIza, Mapbox pk., PostHog phc_): judge the value, not the name.
      const name = /["'`]((?:VITE|REACT_APP|NEXT_PUBLIC)_\w+)["'`]/.exec(m)?.[1] ?? "";
      if (isPublicByDesignValue(val, name) || isPublicByDesignName(name.toLowerCase().replace(/_/g, ""))) return false;
      if (/PLACEHOLDER|YOUR[_-]|EXAMPLE|xxx|yyy|zzz|<|>|\*{3}/i.test(val)) return false;
      // The value must be key material, not the NAME of the variable it stands in for
      // ("VITE_DEEPSEEK_API_KEY": "MY_DEEPSEEK_API_KEY"), nor a reference to one (process.env.X, ${X}, %X%).
      if (looksLikeAName(val) || looksLikeReference(val)) return false;
      return shannonEntropy(val) >= 3.0;
    },
  },

  // ── Database connection URL with credentials ──────────────────────────────
  {
    name: "Database Connection URL with Credentials Exposed",
    pattern: /(?:["'`]|[:=]\s*)(?:postgresql|postgres|mysql|mongodb(?:\+srv)?):\/\/[^:/"'`\s]+:[^@/"'`\s]+@[a-z0-9][^"'`\s]{8,}/i,
    severity: "critical", cvssScore: 10.0, cweId: "CWE-312",
    description: "A database connection URL containing credentials was found in client-side JavaScript. This gives anyone who views your page direct read/write access to your database. In AI-generated apps, database URLs are frequently leaked by accidentally using VITE_DATABASE_URL or similar env var names.",
    solution: "EMERGENCY: Immediately rotate your database credentials. Remove the connection URL from all frontend code. Database connections must only be made from server-side code. If using Supabase/Neon/PlanetScale, use their client libraries on the frontend with proper Row Level Security — never pass the full connection URL to the browser.",
    validate: (m) => {
      if (/example|sample/i.test(m)) return false;
      const parts = /:\/\/([^:/@\s"'`]+):([^@/\s"'`]+)@([^:/?\s"'`]+)/.exec(m);
      if (!parts) return false;
      const [, user = "", pass = "", host = ""] = parts;
      // A URL that reaches only the developer's own machine leaks nothing, whatever its password.
      if (isLocalHost(host)) return false;
      // Require an actual password: non-empty, not a tutorial default (postgres:postgres,
      // root:toor1234, user == password), not a template or a reference.
      if (pass === "" || /password|passwd|pass|secret|changeme|yourpass/i.test(pass)) return false;
      if (isTrivialPassword(pass, user) || looksLikeReference(pass) || isPlaceholderToken(pass)) return false;
      return pass.length >= 8;
    },
  },

  // ── Mapbox ────────────────────────────────────────────────────────────────
  {
    name: "Mapbox Public Token — Restrict to Your Domain",
    // pk.ey… is a PUBLIC token by design (Mapbox secret tokens start with sk.ey…).
    // Flagged as info — the real risk is an unrestricted token used on other domains.
    pattern: /\bpk\.ey[0-9A-Za-z._-]{50,}/,
    severity: "info", cvssScore: 2.6, cweId: "CWE-200",
    description: "A Mapbox public access token (pk.ey…) was found in client-side JavaScript. Mapbox public tokens are intentionally designed to be embedded in frontend code — this is not a secret. However, an unrestricted token can be copied and used on any domain, incurring API charges on your account.",
    solution: "In the Mapbox account dashboard → Access Tokens, add an 'Allowed URL' restriction for your production domain. This prevents the token from being used on other domains even if extracted from your bundle. Note: sk.ey… (secret) tokens must NEVER appear in frontend code.",
  },
];

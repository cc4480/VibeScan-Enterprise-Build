/**
 * JavaScript secret scanner — detects hardcoded credentials and sensitive data
 * in inline scripts and external JavaScript files linked from the target page.
 *
 * Patterns cover: AWS, Google, Stripe, GitHub, Slack, Twilio, SendGrid,
 * Mailchimp, private keys, JWTs, Firebase, and generic credential patterns.
 *
 * Only runs on "deep" tier scans to avoid excessive external HTTP requests.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

/**
 * Shannon entropy of a string — bits per character.
 * Real secret keys score > 3.5; placeholders / repeating patterns score < 3.0.
 * Used to filter low-entropy false positives in generic secret patterns.
 */
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  const len = s.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

const JS_FETCH_TIMEOUT_MS = 10_000;
const MAX_EXTERNAL_SCRIPTS = 8;
const MAX_SCRIPT_SIZE_BYTES = 512_000; // 512 KB per file

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─────────────────────────────────────────────────────────────────────────────
// SECRET PATTERNS
// ─────────────────────────────────────────────────────────────────────────────

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: ScanVulnerability["severity"];
  cvssScore?: number;
  description: string;
  solution: string;
  cweId: string;
  // Return false to suppress a match (false positive filter)
  validate?: (match: string) => boolean;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    name: "AWS Access Key ID Exposed",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-798",
    description: "A live AWS Access Key ID was found in client-side JavaScript. Combined with the Secret Access Key (often nearby in the same file), this allows full AWS account access — exfiltrating S3 data, spinning up EC2 instances, accessing RDS databases, and incurring massive costs.",
    solution: "Immediately revoke this key in the AWS IAM console. Never hardcode AWS credentials in frontend code. Use IAM roles for server-side access. For client-side AWS use, use AWS Cognito Identity Pools with least-privilege scoped temporary credentials.",
    validate: (m) => !/(EXAMPLE|SAMPLE|FAKE|TEST|DEMO|PLACEHOLDER|REDACTED|XXXX)/i.test(m),
  },
  {
    name: "AWS Secret Access Key Exposed",
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secretAccessKey|secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/i,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-798",
    description: "An AWS Secret Access Key was found in client-side JavaScript. This grants API-level access to AWS services.",
    solution: "Immediately revoke this key. Move AWS calls to a backend proxy that uses IAM roles. Never include AWS secrets in frontend bundles.",
    validate: (m) => !/EXAMPLE|SAMPLE|FAKE|TEST|PLACEHOLDER/i.test(m),
  },

  // ── Google ────────────────────────────────────────────────────────────────
  {
    name: "Google API Key Exposed",
    pattern: /AIza[0-9A-Za-z\-_]{35}/,
    severity: "high", cvssScore: 7.5, cweId: "CWE-798",
    description: "A Google API Key was found in client-side code. Depending on which APIs are enabled and whether the key has referrer/IP restrictions, attackers can abuse billing-metered APIs (Maps, Places, Vision, Translate), exfiltrate data, or run up large charges on your account.",
    solution: "Restrict the API key to specific HTTP referrers and APIs in the Google Cloud Console. For server-side APIs, move the key to the backend. Regularly audit key usage for anomalies in the Cloud Console.",
    validate: (m) => !/EXAMPLE|SAMPLE|YOUR.API.KEY/i.test(m),
  },
  {
    name: "Google OAuth Client Secret Exposed",
    pattern: /GOCSPX-[0-9A-Za-z\-_]{28}/,
    severity: "critical", cvssScore: 9.1, cweId: "CWE-798",
    description: "A Google OAuth Client Secret was found in client-side code. This allows attackers to impersonate your application in OAuth flows and potentially hijack user authentication.",
    solution: "Immediately rotate the OAuth client secret in Google Cloud Console. Client secrets must never be in frontend code — keep them server-side only.",
  },

  // ── Stripe ────────────────────────────────────────────────────────────────
  {
    name: "Stripe Live Secret Key Exposed",
    pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-798",
    description: "A Stripe live secret key was found in client-side JavaScript. This allows attackers to charge any payment method, access all customer data, issue refunds, create fraudulent transfers, and completely compromise your payment infrastructure.",
    solution: "Immediately revoke this key in the Stripe Dashboard. Stripe secret keys must ONLY be used server-side. Use Stripe.js (publishable key) for client-side payment collection.",
    validate: (m) => !/(test|EXAMPLE)/i.test(m),
  },
  {
    name: "Stripe Test Secret Key in Production",
    pattern: /\bsk_test_[0-9a-zA-Z]{24,}\b/,
    severity: "medium", cvssScore: 5.3, cweId: "CWE-798",
    description: "A Stripe test mode secret key was found in client-side JavaScript. While it cannot charge real cards, its presence indicates that secret keys are being improperly included in frontend bundles — suggesting the production secret key may also be exposed elsewhere.",
    solution: "Remove all secret keys from frontend code. Even test keys should not be exposed as they reveal your key pattern and confirm you're using Stripe.",
  },
  {
    name: "Stripe Webhook Secret Exposed",
    pattern: /\bwhsec_[0-9a-zA-Z]{32,}\b/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A Stripe webhook signing secret was found in client-side code. This allows attackers to forge webhook events, potentially triggering payment confirmations, subscription activations, or other business logic without actual payments.",
    solution: "Rotate this webhook secret in the Stripe Dashboard. Webhook secrets are server-side only — they should never appear in frontend code.",
  },

  // ── GitHub ────────────────────────────────────────────────────────────────
  {
    name: "GitHub Personal Access Token Exposed",
    pattern: /\bgh[pousr]_[0-9a-zA-Z]{36,}\b/,
    severity: "critical", cvssScore: 9.1, cweId: "CWE-798",
    description: "A GitHub Personal Access Token (PAT) was found in client-side JavaScript. Depending on its scopes, this allows reading private repositories, modifying code, accessing secrets, and interacting with the entire GitHub API on behalf of the token owner.",
    solution: "Immediately revoke this token on GitHub (Settings → Developer settings → Personal access tokens). If this token had repo scope, assume all private repos it could access have been compromised.",
    validate: (m) => !/(EXAMPLE|TOKEN_HERE|YOUR_TOKEN)/i.test(m),
  },
  {
    name: "GitHub Fine-Grained Access Token Exposed",
    pattern: /\bgithub_pat_[0-9a-zA-Z_]{82,}\b/,
    severity: "critical", cvssScore: 9.1, cweId: "CWE-798",
    description: "A GitHub fine-grained access token was found in client-side JavaScript.",
    solution: "Immediately revoke this token in GitHub Settings. GitHub tokens must never be embedded in client-side code.",
  },

  // ── Slack ─────────────────────────────────────────────────────────────────
  {
    name: "Slack Bot/OAuth Token Exposed",
    pattern: /xox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z]{10,}/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A Slack API token was found in client-side JavaScript. This allows reading all messages in accessible channels, sending messages as the bot/user, accessing files, and enumerating workspace members.",
    solution: "Immediately revoke this token in the Slack API console (api.slack.com/apps). Slack tokens must be used server-side only — never in frontend bundles.",
    validate: (m) => !/(EXAMPLE|YOUR.TOKEN|xoxb-000)/i.test(m),
  },
  {
    name: "Slack Incoming Webhook URL Exposed",
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24,}/,
    severity: "medium", cvssScore: 5.3, cweId: "CWE-798",
    description: "A Slack incoming webhook URL was found in client-side code. Anyone with this URL can post arbitrary messages to your Slack channel — enabling internal phishing, social engineering, and information injection attacks.",
    solution: "Rotate the webhook in Slack (delete and recreate). Move webhook calls to a backend proxy. If internal alerting is needed from the browser, use a server endpoint that validates and proxies the message.",
  },

  // ── Twilio ────────────────────────────────────────────────────────────────
  {
    name: "Twilio API Key Exposed",
    pattern: /SK[0-9a-fA-F]{32}/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A Twilio API key was found in client-side JavaScript. This can be used to send SMS messages (billing abuse), make phone calls, access conversation data, and more.",
    solution: "Revoke this key in the Twilio console. Move all Twilio API calls to a backend service. Never include API keys in frontend JavaScript.",
    validate: (m) => !/SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/.test(m),
  },

  // ── Supabase (new June 2025 key formats) ─────────────────────────────────
  {
    name: "Supabase Service Role Key Exposed (sb_secret_)",
    // sb_secret_* = admin-tier key with BYPASSRLS — never belongs in frontend code
    pattern: /\bsb_secret_[a-zA-Z0-9_-]{20,}\b/,
    severity: "critical", cvssScore: 10.0, cweId: "CWE-798",
    description:
      "A Supabase secret key (sb_secret_…) was found in client-side JavaScript. " +
      "This is an admin-tier credential introduced in the June 2025 key format update — it carries " +
      "BYPASSRLS privilege, ignoring all Row Level Security policies and granting unrestricted " +
      "read/write/delete access to your entire database.",
    solution:
      "EMERGENCY: Rotate this key immediately in Supabase Dashboard → Settings → API. " +
      "Remove it from all frontend code. Use the publishable key (sb_publishable_…) for " +
      "client-side operations and enforce access via RLS policies.",
  },
  // Note: sb_publishable_* keys are NOT flagged — they are public-by-design (anon-tier).
  // Security comes from RLS policies, not key secrecy. The BaaS probe handles table checks.

  // ── Sentry ────────────────────────────────────────────────────────────────
  // Sentry DSNs (https://xxx@sentry.io/project) are INTENTIONALLY public — they are
  // ingest-only identifiers. We deliberately do NOT flag them as findings.
  // Only Sentry auth tokens (sntrys_* or the legacy hex format) grant API access.
  {
    name: "Sentry Auth Token Exposed",
    // New format: sntrys_eyJ… (JWT-style, issued since ~2024)
    pattern: /\bsntrys_eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}\b/,
    severity: "critical", cvssScore: 8.5, cweId: "CWE-798",
    description:
      "A Sentry authentication token was found in client-side JavaScript. Unlike a Sentry DSN " +
      "(which is public/ingest-only), an auth token grants full API access — reading all events, " +
      "issues, releases, and project settings. It can also be used to exfiltrate error messages " +
      "that may contain sensitive user data.",
    solution:
      "Revoke this token immediately in Sentry Settings → Auth Tokens. " +
      "Auth tokens are server-side only — they must never appear in frontend bundles. " +
      "If you need to use Sentry from the frontend, use only the DSN (project identifier), " +
      "which is safe to expose.",
  },
  {
    name: "Sentry Auth Token Exposed (legacy format)",
    // Legacy format: 64-char hex string in auth token context
    pattern: /(?:SENTRY_AUTH_TOKEN|sentry[_-]?token|sentry[_-]?auth)\s*[:=]\s*["']([a-f0-9]{64})["']/i,
    severity: "critical", cvssScore: 8.5, cweId: "CWE-798",
    description:
      "A Sentry authentication token (legacy 64-char hex format) was found in client-side JavaScript. " +
      "This grants full API access to your Sentry organization — reading errors, issues, user data, " +
      "and project configurations.",
    solution:
      "Revoke this token in Sentry Settings → Auth Tokens and remove it from frontend code. " +
      "Auth tokens must be server-side only.",
    validate: (m) => !/EXAMPLE|PLACEHOLDER|YOUR_TOKEN|x{16,}/i.test(m),
  },

  // ── SendGrid / Email ──────────────────────────────────────────────────────
  {
    name: "SendGrid API Key Exposed",
    pattern: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A SendGrid API key was found in client-side code. This allows sending unlimited emails as your domain — ideal for spam campaigns, phishing attacks, and burning your sending reputation.",
    solution: "Immediately revoke this key in the SendGrid dashboard. Email sending keys belong server-side only.",
  },
  {
    name: "Mailchimp API Key Exposed",
    // Require an explicit key-assignment context — the bare hex-us pattern is too broad
    // (any 32-hex string followed by -us[1-2] could match unrelated identifiers).
    pattern: /(?:apiKey|api_key|mc_api|mailchimp(?:_key|Key|_api)?|MAILCHIMP_KEY)\s*[:=,\s]+["'`]?([0-9a-f]{32}-us[0-9]{1,2})["'`]?/i,
    severity: "high", cvssScore: 7.5, cweId: "CWE-798",
    description: "A Mailchimp API key was found in client-side JavaScript. This provides full access to your email lists, campaigns, and subscriber data — including the ability to export all subscriber emails.",
    solution: "Rotate this API key in the Mailchimp account settings (Account → Extras → API Keys). Move all Mailchimp API calls to a backend service. Never expose email marketing credentials in frontend code.",
    validate: (m) => /[0-9a-f]{32}-us[0-9]{1,2}/.test(m),
  },

  // ── Cryptographic Keys ────────────────────────────────────────────────────
  {
    name: "Private Key Exposed in JavaScript",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: "critical", cvssScore: 10.0, cweId: "CWE-321",
    description: "A cryptographic private key was found in client-side JavaScript. This is an emergency. Private keys are used to sign JWTs, establish TLS connections, authenticate SSH sessions, and more. Anyone who downloads this page has your private key.",
    solution: "EMERGENCY: Immediately revoke and replace this key pair everywhere it is used. Audit all systems that accepted this key for unauthorized access. Private keys must NEVER exist in frontend code under any circumstances.",
  },

  // ── Firebase ─────────────────────────────────────────────────────────────
  {
    name: "Firebase API Key with Open Security Rules",
    pattern: /firebaseConfig\s*=\s*\{[^}]*apiKey:\s*["'][^"']+["'][^}]*\}/,
    severity: "info", cvssScore: 3.1, cweId: "CWE-798",
    description: "A Firebase configuration block was found in client-side JavaScript. Firebase API keys are semi-public (they identify your project), but if your Firestore/Realtime Database security rules are too permissive, attackers can read or write data using these credentials.",
    solution: "Review your Firestore and Realtime Database security rules to ensure they enforce proper authentication and authorization. Enable App Check to prevent abuse. The API key itself is not a secret but permissive rules are the real risk.",
  },

  // ── JSON Web Tokens ───────────────────────────────────────────────────────
  {
    name: "Hardcoded JWT Token in Source",
    pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A JWT (JSON Web Token) was found hardcoded in JavaScript source code. If this is a long-lived or non-expiring token, anyone who views this code is authenticated as the associated user or service account.",
    solution: "Immediately invalidate this token (rotate the JWT signing secret, or if using a token allowlist, remove this token). Never hardcode JWTs in source code. Tokens should be dynamically obtained at runtime and stored in memory, not in code.",
    validate: (m) => {
      // Skip very short tokens that are likely examples
      return m.length > 60;
    },
  },

  // ── Generic Secrets ───────────────────────────────────────────────────────
  {
    name: "Hardcoded Password in Source Code",
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
      // Require reasonable entropy — real passwords aren't all-same-char repeating strings
      return shannonEntropy(val) >= 2.5;
    },
  },
  {
    name: "Hardcoded Secret Key or Token in Source",
    pattern: /(?:secret|api_key|apikey|auth_token|access_token)\s*[:=]\s*["']([a-zA-Z0-9\-_+/]{16,})["']/i,
    severity: "medium", cvssScore: 6.5, cweId: "CWE-798",
    description: "A hardcoded secret key or token was found in client-side JavaScript. Keys and tokens embedded in frontend code are accessible to anyone who visits the site.",
    solution: "Move API keys and tokens to the backend. Use short-lived, scoped tokens issued by your backend for any client-side API calls.",
    validate: (m) => {
      if (/your[_-]?(api[_-]?)?key|insert[_-]?key|replace[_-]?me|XXXXXXXX/i.test(m)) return false;
      if (/EXAMPLE|PLACEHOLDER|YOUR_|<|>|\*{3,}|\.{3,}/i.test(m)) return false;
      // Extract the value portion and validate entropy
      const valMatch = /[:=]\s*["']([^"']+)["']/.exec(m);
      if (!valMatch) return false;
      // Low-entropy strings (all same chars, simple sequences) are likely placeholders
      return shannonEntropy(valMatch[1]) >= 3.0;
    },
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
    validate: (m) => {
      // Skip clearly benign/example contexts
      if (/example|sample|demo|placeholder|comment|doc|test/i.test(m)) return false;
      if (/192\.168\.1\.(1|0|255)\b/.test(m) && /(?:gateway|router|default)/i.test(m)) return false;
      return true;
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

// ─────────────────────────────────────────────────────────────────────────────
// EXTRACT SCRIPT CONTENT
// ─────────────────────────────────────────────────────────────────────────────

async function fetchScript(url: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), JS_FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return "";
    const ct = res.headers.get("content-type") ?? "";
    if (!ct.includes("javascript") && !ct.includes("text/plain") && !ct.includes("application/")) return "";
    const body = await res.text();
    return body.slice(0, MAX_SCRIPT_SIZE_BYTES);
  } catch {
    return "";
  } finally {
    clearTimeout(timer);
  }
}

function extractInlineScripts(html: string): string {
  const inlineRegex = /<script(?:[^>]*)>([\s\S]*?)<\/script>/gi;
  const parts: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = inlineRegex.exec(html)) !== null) {
    const tag = m[0];
    // Skip external scripts (they have a src attribute)
    if (!/\bsrc\s*=/i.test(tag)) {
      parts.push(m[1] ?? "");
    }
  }
  return parts.join("\n");
}

function extractExternalScriptUrls(html: string, baseUrl: string): string[] {
  const srcRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  const urls: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = srcRegex.exec(html)) !== null) {
    try {
      const absolute = new URL(m[1], baseUrl).href;
      urls.push(absolute);
    } catch { /* invalid URL */ }
  }
  return [...new Set(urls)].slice(0, MAX_EXTERNAL_SCRIPTS);
}

// ─────────────────────────────────────────────────────────────────────────────
// SCAN FOR SECRETS
// ─────────────────────────────────────────────────────────────────────────────

function redactSecret(match: string): string {
  if (match.length <= 8) return "***";
  return match.slice(0, 6) + "..." + match.slice(-4);
}

function scanContent(content: string): Array<{ pattern: SecretPattern; match: string; context: string }> {
  const findings: Array<{ pattern: SecretPattern; match: string; context: string }> = [];

  for (const p of SECRET_PATTERNS) {
    const globalPattern = new RegExp(p.pattern.source, "g" + (p.pattern.flags.includes("i") ? "i" : ""));
    let m: RegExpExecArray | null;
    while ((m = globalPattern.exec(content)) !== null) {
      const match = m[0];
      if (p.validate && !p.validate(match)) continue;

      // Get surrounding context (2 lines before/after)
      const start = Math.max(0, m.index - 100);
      const end = Math.min(content.length, m.index + match.length + 100);
      const context = content.slice(start, end).replace(/\n/g, " ").trim();

      findings.push({ pattern: p, match, context });
      break; // Only report once per pattern per file
    }
  }

  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function scanJavaScriptForSecrets(
  html: string,
  baseUrl: string,
): Promise<ScanVulnerability[]> {
  // 1. Scan inline scripts immediately
  const inlineContent = extractInlineScripts(html);
  const inlineFindings = scanContent(inlineContent);

  // 2. Fetch and scan external scripts in parallel
  const externalUrls = extractExternalScriptUrls(html, baseUrl);
  const externalContents = await Promise.allSettled(
    externalUrls.map((url) => fetchScript(url)),
  );

  const allExternalFindings: Array<{ pattern: SecretPattern; match: string; context: string; url: string }> = [];
  externalContents.forEach((result, i) => {
    if (result.status === "fulfilled" && result.value) {
      const findings = scanContent(result.value);
      findings.forEach((f) => allExternalFindings.push({ ...f, url: externalUrls[i] }));
    }
  });

  // 3. Deduplicate findings by pattern name
  const seen = new Set<string>();
  const vulns: ScanVulnerability[] = [];

  for (const f of inlineFindings) {
    if (seen.has(f.pattern.name)) continue;
    seen.add(f.pattern.name);
    vulns.push(vuln({
      name: f.pattern.name,
      severity: f.pattern.severity,
      category: "Exposed Secrets / Credentials",
      description: f.pattern.description,
      evidence: `Source: inline <script> block\nMatch (redacted): ${redactSecret(f.match)}\nContext: ...${f.context.slice(0, 200)}...`,
      solution: f.pattern.solution,
      cweId: f.pattern.cweId,
      cvssScore: f.pattern.cvssScore,
      wstgId: "WSTG-CONF-04",
    }));
  }

  for (const f of allExternalFindings) {
    if (seen.has(f.pattern.name)) continue;
    seen.add(f.pattern.name);
    const scriptPath = (() => { try { return new URL(f.url).pathname; } catch { return f.url; } })();
    vulns.push(vuln({
      name: f.pattern.name,
      severity: f.pattern.severity,
      category: "Exposed Secrets / Credentials",
      description: f.pattern.description,
      evidence: `Source: external script ${scriptPath}\nMatch (redacted): ${redactSecret(f.match)}\nContext: ...${f.context.slice(0, 200)}...`,
      solution: f.pattern.solution,
      cweId: f.pattern.cweId,
      cvssScore: f.pattern.cvssScore,
      wstgId: "WSTG-CONF-04",
    }));
  }

  return vulns;
}

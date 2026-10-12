import type { SecretPattern } from "./secret-pattern-data";
import { shannonEntropy } from "./secretPlaceholders";

/** One finding text for the Supabase service_role key, whether it is found by a variable name or by decoding the token (secret-pattern-jwt.ts). */
export const SERVICE_ROLE_DESCRIPTION = "The Supabase service_role key was found in an external JavaScript file. Unlike the anon key — which is public by design — the service_role key bypasses ALL Row Level Security policies on every table, giving any visitor full admin read/write/delete access to your entire database. This is the most dangerous Supabase misconfiguration possible.";
export const SERVICE_ROLE_SOLUTION = "Immediately rotate this key in the Supabase dashboard (Project Settings → API → Reset service_role key). Remove it from all frontend code. The service_role key belongs exclusively in server-side code (Edge Functions, your own backend). For client-side use, the anon key is correct and safe to expose.";

/** Secret patterns for named vendors (cloud, payments, VCS, chat, BaaS, email, keys, Firebase). */
export const VENDOR_SECRET_PATTERNS: SecretPattern[] = [
  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    name: "AWS Access Key ID Found in Client Code",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    // An access key ID is an identifier: it cannot sign a request without its Secret Access Key.
    // The secret half is a separate pattern below, and is Critical when it is found.
    severity: "low", cvssScore: 3.7, cweId: "CWE-200",
    description: "An AWS Access Key ID (AKIA…) was found in client-side JavaScript. On its own an access key ID is an identifier, not a credential: requests cannot be signed without the matching Secret Access Key, and none was matched beside this one. It does name the AWS account's IAM user, and if the secret half is also present in this code (search for it) the pair gives API access to whatever that user may do.",
    solution: "Check whether the matching Secret Access Key is reachable from the browser too, and if this ID belongs to a real IAM user rotate it in the IAM console. Never hardcode AWS credentials in frontend code. Use IAM roles for server-side access; for client-side AWS use, use Cognito Identity Pools with least-privilege temporary credentials.",
    validate: (m) => !/(EXAMPLE|SAMPLE|FAKE|TEST|DEMO|PLACEHOLDER|REDACTED|XXXX)/i.test(m),
  },
  {
    name: "AWS Secret Access Key Exposed",
    // An explicit AWS name, or the generic `secret_key` only with an access key ID in the same
    // breath: `secret_key` alone also names CSRF, session and signing secrets, and any 40-character
    // string (a SHA-1) fits the value shape.
    pattern: /(?:aws_secret_access_key|secretAccessKey)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])|A[KS]IA[0-9A-Z]{16}[\s\S]{0,200}?secret_?key\s*[=:]\s*["'][A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])|secret_?key\s*[=:]\s*["'][A-Za-z0-9/+=]{40}["'][\s\S]{0,200}?A[KS]IA[0-9A-Z]{16}/i,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-798",
    description: "A value in the shape of an AWS Secret Access Key was found in client-side JavaScript, assigned to a secret-key name (an AWS-specific one, or `secret_key` beside an AWS access key ID). If it is real, it grants API-level access to AWS services as its IAM user.",
    solution: "Immediately revoke this key. Move AWS calls to a backend proxy that uses IAM roles. Never include AWS secrets in frontend bundles.",
    validate: (m) => {
      if (/EXAMPLE|SAMPLE|FAKE|TEST|PLACEHOLDER/i.test(m)) return false;
      const value = [...m.matchAll(/[=:]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/g)].pop()?.[1] ?? "";
      // Never a hex digest, and random base64 (about 5 bits per character), not repetition or words.
      return value !== "" && !/^[0-9a-f]{40}$/i.test(value) && shannonEntropy(value) >= 4.0;
    },
  },

  // ── Google ────────────────────────────────────────────────────────────────
  {
    name: "Google API Key in Client Code (verify referrer restrictions)",
    pattern: /AIza[0-9A-Za-z\-_]{35}/,
    // Info, not High. An AIza key is browser-facing by design — Maps, YouTube
    // embeds and Firebase all ship one to the client, and Google's own
    // properties do too (this fired High on youtube.com's public embed key).
    // Its presence is therefore expected, not evidence of a leak. The only real
    // risk is a key left *unrestricted*, and that cannot be proven from the
    // page alone. Reporting it Info "verify restrictions" is consistent with how
    // Firebase AIza keys and Stripe pk_live_ publishable keys are already
    // treated — flag the thing to check, do not cry breach over a public value.
    severity: "info", cvssScore: 0, cweId: "CWE-798",
    description: "A Google API key (AIza…) was found in client-side code. These keys are designed to be public — Google Maps, YouTube embeds and Firebase all expose one to the browser — so this alone is not a vulnerability. It becomes a risk only if the key is left without HTTP-referrer or API restrictions, which cannot be determined from the page. This is a prompt to verify, not a confirmed exposure.",
    solution: "In the Google Cloud Console, confirm this key is restricted to your specific HTTP referrers and to only the APIs it needs. An unrestricted key can be used from anywhere and can run up billing on metered APIs (Maps, Places, Vision). Server-side-only keys must never appear in client code at all.",
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
    name: "Stripe Test-Mode Secret Key in Client Code",
    pattern: /\bsk_test_[0-9a-zA-Z]{24,}\b/,
    severity: "medium", cvssScore: 5.3, cweId: "CWE-798",
    description: "A Stripe test-mode secret key (sk_test_…) was found in client-side JavaScript. It cannot charge real cards, and whether this is a production site or a staging or preview build cannot be told from the page. A secret key of any mode does not belong in browser code: it shows secret keys are being included in the frontend bundle, and it grants full test-mode API access to the account.",
    solution: "Remove all secret keys from frontend code and roll this test key in the Stripe Dashboard. Check the build for a live-mode secret key (sk_live_…) shipped the same way. Use only the publishable key (pk_…) in the browser.",
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
    // The SID (SK…) is an identifier, like an AWS access key ID: requests are signed with the secret
    // half, which is 32 plain characters with no prefix and so can only be recognised by its name.
    name: "Twilio API Key SID and Secret Exposed",
    pattern: /\bSK[0-9a-fA-F]{32}\b[\s\S]{0,160}?(?:[Ss]ecret|SECRET)\w*["']?\s*[:=,]\s*["']?[0-9A-Za-z]{32}\b|(?:[Ss]ecret|SECRET)\w*["']?\s*[:=,]\s*["']?[0-9A-Za-z]{32}["']?[\s\S]{0,160}?\bSK[0-9a-fA-F]{32}\b/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-798",
    description: "A Twilio API Key SID (SK…) was found in client-side JavaScript next to a 32-character value assigned to a secret-named property. Together they are the credential pair that signs Twilio API requests: sending SMS (billing abuse), making calls, and reading conversation data.",
    solution: "Revoke this key in the Twilio console. Move all Twilio API calls to a backend service. Never include API keys in frontend JavaScript.",
    validate: (m) => !/SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/.test(m),
  },
  {
    name: "Twilio API Key SID Found in Client Code",
    pattern: /\bSK[0-9a-fA-F]{32}\b/,
    severity: "info", cvssScore: 0, cweId: "CWE-200",
    description: "A Twilio API Key SID (SK…) was found in client-side JavaScript. A SID only identifies a key: it cannot be used to call Twilio without the API secret, and no secret was matched beside it. This is a prompt to confirm the secret is not also shipped to the browser, not a confirmed exposure.",
    solution: "Confirm the API secret paired with this SID is only used server-side. Twilio Voice and Video SDKs use short-lived access tokens minted by your backend rather than a key in the page.",
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
  {
    name: "Supabase Service Role Key Exposed in JavaScript",
    // Legacy format: literal variable name holding a service_role JWT.
    pattern: /(?:serviceRoleKey|service_role_key|SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE_KEY)\s*[:=]\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/i,
    severity: "critical", cvssScore: 10.0, cweId: "CWE-522",
    description: SERVICE_ROLE_DESCRIPTION,
    solution: SERVICE_ROLE_SOLUTION,
  },

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
    skipPlaceholderCheck: true,
    // The PEM header alone proves nothing. Crypto libraries embed it as a
    // formatting template: JSEncrypt — common on bank login forms — ships
    // `getPrivateKey = function () { var t = "-----BEGIN RSA PRIVATE KEY-----" ... }`
    // with no key anywhere near it. That bare header fired a CVSS 10.0 Critical
    // on capitalone.com, and would on every site loading the library.
    // Require real base64 key material to follow. The separator class allows an
    // escaped newline, since inside a JS string literal the break between the
    // header and the key body is a backslash-n rather than an actual newline.
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\\rn"']{0,12}[A-Za-z0-9+/]{40,}/,
    severity: "critical", cvssScore: 10.0, cweId: "CWE-321",
    description: "A cryptographic private key was found in client-side JavaScript. This is an emergency. Private keys are used to sign JWTs, establish TLS connections, authenticate SSH sessions, and more. Anyone who downloads this page has your private key.",
    solution: "EMERGENCY: Immediately revoke and replace this key pair everywhere it is used. Audit all systems that accepted this key for unauthorized access. Private keys must NEVER exist in frontend code under any circumstances.",
  },

  // ── Firebase ─────────────────────────────────────────────────────────────
  {
    name: "Firebase Configuration Found in Client Code",
    skipPlaceholderCheck: true,
    pattern: /firebaseConfig\s*=\s*\{[^}]*apiKey:\s*["'][^"']+["'][^}]*\}/,
    severity: "info", cvssScore: 3.1, cweId: "CWE-798",
    description: "A Firebase configuration block (firebaseConfig with an apiKey) was found in client-side JavaScript. Firebase web API keys are public by design: they identify your project, and shipping one is how the SDK works. This match cannot tell whether the project's Firestore or Realtime Database security rules are open or properly restrictive, so it is a prompt to check them, not a finding that they are permissive.",
    solution: "Review your Firestore and Realtime Database security rules to ensure they enforce proper authentication and authorization. Enable App Check to prevent abuse. The API key itself is not a secret but permissive rules are the real risk.",
  },

];

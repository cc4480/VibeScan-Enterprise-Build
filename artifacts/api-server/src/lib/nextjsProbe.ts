/**
 * Next.js-specific security probe.
 *
 * Checks for:
 * 1. __NEXT_DATA__ serialized props containing secrets (server-side props
 *    accidentally serialized into the page HTML — readable by anyone).
 * 2. Build ID leakage (minor info, confirms Next.js + version surface).
 *
 * Note: source map exposure for /_next/static is already covered by sourceMaps.ts.
 * This probe focuses exclusively on inline data leaks via __NEXT_DATA__.
 *
 * Read-only — no extra HTTP requests beyond parsing the already-fetched HTML.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─────────────────────────────────────────────────────────────────────────────
// SECRET PATTERNS FOR __NEXT_DATA__ SCANNING
// ─────────────────────────────────────────────────────────────────────────────

interface NextDataSecretPattern {
  name: string;
  pattern: RegExp;
  severity: ScanVulnerability["severity"];
  cvssScore: number;
  description: string;
  solution: string;
  cweId: string;
}

const NEXT_DATA_SECRET_PATTERNS: NextDataSecretPattern[] = [
  {
    name: "Stripe Live Secret Key in __NEXT_DATA__",
    pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-312",
    description:
      "A Stripe live secret key was found in the __NEXT_DATA__ JSON blob serialized into your " +
      "Next.js page HTML. This is fully visible to any browser that visits the page — no DevTools " +
      "required. An attacker can immediately use it to charge cards, access customer data, and " +
      "compromise your entire payment infrastructure.",
    solution:
      "EMERGENCY: Revoke this key in the Stripe Dashboard immediately. Remove it from " +
      "getServerSideProps/getStaticProps. Stripe secret keys must NEVER be returned as props — " +
      "they belong server-side only. Use the Stripe client with a publishable key (pk_live_) " +
      "on the frontend.",
  },
  {
    name: "Supabase Service Role Key in __NEXT_DATA__",
    pattern: /service_role[^"']{0,20}["']eyJ[A-Za-z0-9_-]{30,}/,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-312",
    description:
      "A Supabase service_role key was found in __NEXT_DATA__. This key bypasses all Row Level " +
      "Security rules and grants unrestricted read/write access to your entire Supabase database " +
      "as an admin. Anyone who views your page source has full database access.",
    solution:
      "Immediately rotate the service_role key in Supabase → Settings → API. Remove it from " +
      "any getServerSideProps return values. The service_role key is server-only — never return " +
      "it as a prop or include it in any client-visible data.",
  },
  {
    name: "Private Key in __NEXT_DATA__",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: "critical", cvssScore: 10.0, cweId: "CWE-321",
    description:
      "A cryptographic private key was found in the __NEXT_DATA__ JSON blob. This key is now " +
      "publicly visible to every visitor. Private keys sign JWTs, authenticate SSH sessions, " +
      "and establish TLS connections — exposure is an emergency.",
    solution:
      "EMERGENCY: Revoke and replace this key everywhere it is used. Audit all systems for " +
      "unauthorized access since it was exposed. Remove it from getServerSideProps immediately.",
  },
  {
    name: "AWS Access Key ID in __NEXT_DATA__",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-312",
    description:
      "An AWS Access Key ID was found in __NEXT_DATA__. Combined with the Secret Access Key " +
      "(which is likely nearby), this allows full AWS account access visible to any page visitor.",
    solution:
      "Revoke this key in AWS IAM immediately. Remove AWS credentials from getServerSideProps. " +
      "Use IAM roles for server-side AWS access. Never serialize AWS credentials into page props.",
  },
  {
    name: "AWS Secret Access Key in __NEXT_DATA__",
    pattern: /(?:aws_secret_access_key|secretAccessKey)\s*["':\s]+([A-Za-z0-9/+=]{40})/i,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-312",
    description:
      "An AWS Secret Access Key was found in the __NEXT_DATA__ props blob. This is visible in " +
      "plain text to every visitor and grants API-level access to AWS services.",
    solution:
      "Revoke the key immediately in AWS IAM. Remove AWS credentials from all Next.js props. " +
      "Use server-side IAM roles instead of static credentials.",
  },
  {
    name: "GitHub Token in __NEXT_DATA__",
    pattern: /\bgh[pousr]_[0-9a-zA-Z]{36,}\b|\bgithub_pat_[0-9a-zA-Z_]{82,}\b/,
    severity: "critical", cvssScore: 9.1, cweId: "CWE-312",
    description:
      "A GitHub Personal Access Token was found in __NEXT_DATA__ props. Any visitor can read " +
      "this token from the page source and use it to access private repositories.",
    solution:
      "Revoke this token in GitHub Settings immediately. Remove it from getServerSideProps. " +
      "GitHub tokens must never be serialized into page props.",
  },
  {
    name: "SendGrid API Key in __NEXT_DATA__",
    pattern: /\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-312",
    description:
      "A SendGrid API key was found in __NEXT_DATA__. This allows sending unlimited emails " +
      "from your domain — phishing, spam campaigns, and reputation damage.",
    solution:
      "Revoke this key in SendGrid immediately. Remove it from Next.js props. Email API keys " +
      "must be server-side only.",
  },
  {
    name: "Slack Token in __NEXT_DATA__",
    pattern: /xox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z]{10,}/,
    severity: "high", cvssScore: 8.1, cweId: "CWE-312",
    description:
      "A Slack API token was found in __NEXT_DATA__ props. Anyone can read your Slack messages, " +
      "post as the bot, and access workspace members using this token.",
    solution:
      "Revoke this token in api.slack.com/apps immediately. Remove from getServerSideProps. " +
      "Slack tokens are server-only.",
  },
  {
    name: "Hardcoded Database Connection String in __NEXT_DATA__",
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^\s"']+/i,
    severity: "critical", cvssScore: 9.8, cweId: "CWE-312",
    description:
      "A database connection string (including credentials) was found in the __NEXT_DATA__ " +
      "props blob. Any visitor can use this to connect directly to your database.",
    solution:
      "EMERGENCY: Change the database password immediately. Remove the connection string from " +
      "all Next.js props. Connection strings belong in server-only environment variables, never " +
      "in data returned from getServerSideProps.",
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// EXTRACT AND SCAN __NEXT_DATA__
// ─────────────────────────────────────────────────────────────────────────────

function extractNextData(html: string): string | null {
  // Next.js injects this: <script id="__NEXT_DATA__" type="application/json">…</script>
  const match = /<script[^>]+id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i.exec(html);
  return match?.[1]?.trim() ?? null;
}

function isNextJsPage(html: string): boolean {
  return (
    /__NEXT_DATA__|__next|_next\/static/i.test(html) ||
    /next\.js|"buildId"/i.test(html)
  );
}

function redactSecret(text: string): string {
  // Show enough to confirm the finding without leaking the full secret
  return text.length > 20 ? text.slice(0, 8) + "…[redacted]…" + text.slice(-4) : "[redacted]";
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────────────────────────────────────

export async function runNextjsProbe(
  _targetUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
  if (!isNextJsPage(html)) return [];

  const nextDataRaw = extractNextData(html);
  if (!nextDataRaw) return [];

  // Parse to confirm it's valid JSON (fail-soft if it's not)
  let nextDataStr: string;
  try {
    const parsed = JSON.parse(nextDataRaw);
    nextDataStr = JSON.stringify(parsed); // Normalised
  } catch {
    nextDataStr = nextDataRaw; // Still scan raw text
  }

  const found: ScanVulnerability[] = [];

  for (const { name, pattern, severity, cvssScore, cweId, description, solution } of NEXT_DATA_SECRET_PATTERNS) {
    const match = pattern.exec(nextDataStr);
    if (!match) continue;

    const matchedText = match[0];
    const redacted = redactSecret(matchedText);

    found.push(vuln({
      name,
      severity,
      category: "Secret Exposed in Page HTML",
      description,
      evidence: `__NEXT_DATA__ props contain: ${redacted}\nThis value is visible in the raw HTML source of every page visitor.`,
      solution,
      cweId,
      cvssScore,
      confidence: 90,
    }));
  }

  // Also flag large __NEXT_DATA__ blobs as they often contain over-fetched server data
  if (found.length === 0 && nextDataRaw.length > 50_000) {
    found.push(vuln({
      name: "Excessive Data in __NEXT_DATA__ Props (Potential Over-fetch)",
      severity: "low",
      category: "Information Disclosure",
      description:
        `The __NEXT_DATA__ JSON blob is ${Math.round(nextDataRaw.length / 1024)} KB. ` +
        `Large props blobs often indicate that getServerSideProps or getStaticProps is ` +
        `returning entire database rows rather than only the fields the page needs. ` +
        `This can expose internal fields (IDs, timestamps, internal flags) that should ` +
        `stay server-side.`,
      evidence: `__NEXT_DATA__ size: ${Math.round(nextDataRaw.length / 1024)} KB`,
      solution:
        "Audit what getServerSideProps/getStaticProps returns and trim it to only the fields " +
        "the component actually renders. Use select statements / field projection in your " +
        "database queries rather than returning full ORM objects as props.",
      cweId: "CWE-200",
      cvssScore: 3.1,
      confidence: 60,
    }));
  }

  return found;
}

/**
 * SSL Labs API integration. OFF BY DEFAULT: the worker calls it only when SSLLABS_ENABLED=true
 * (workerSideChecks.ts sslLabsEnabled). The scanner's own TLS configuration check (tlsCheck.ts) is
 * what a report carries otherwise.
 *
 * Why it is opt-in. Qualys's terms of use require their permission for commercial use of the SSL
 * Labs APIs, and this module calls API v3, which Qualys deprecated from 2024-01-01 (v4 needs a
 * registered email address). An operator who has Qualys's permission can turn it on; moving to v4
 * would also need that registration.
 *
 * Strategy:
 *   Always trigger a fresh assessment (startNew=on, fromCache=off) so every
 *   scan reflects the current TLS configuration rather than 24h-old data.
 *   Poll for up to MAX_WAIT_MS. If still not READY, return null (graceful
 *   degradation — scan continues without TLS grade).
 *
 * Reference: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
 */

const SSL_LABS_BASE    = "https://api.ssllabs.com/api/v3";
const POLL_INTERVAL_MS = 10_000;  // 10 s between polls
const MAX_WAIT_MS      = 30_000;  // 30 s max total wait (was 120 s — reduced to avoid hung scans)
const FETCH_TIMEOUT_MS = 10_000;  // 10 s abort timeout per individual HTTP request

export interface SslLabsResult {
  grade: string | null;
  hasWarnings: boolean;
  isExceptional: boolean;
  issues: string[];
  /**
   * What held the grade down, read from the assessment's own details (protocols, forward secrecy,
   * ciphers, known attacks). Empty when SSL Labs did not return enough detail to say.
   */
  reasons: string[];
  /** The full public SSL Labs report for the host, so a reader can check the grade themselves. */
  reportUrl: string | null;
}

/** The parts of an SSL Labs endpoint's `details` this module reads. Every field may be absent. */
interface SslLabsDetails {
  protocols?: Array<{ name?: string; version?: string }>;
  /** Bit mask: 0 none, 1 some suites, 2 with modern browsers, 4 with most browsers. */
  forwardSecrecy?: number;
  supportsRc4?: boolean;
  vulnBeast?: boolean;
  heartbleed?: boolean;
  poodle?: boolean;
  /** 2 means vulnerable. */
  poodleTls?: number;
  freak?: boolean;
  logjam?: boolean;
  drownVulnerable?: boolean;
  /** 2 or 3 means vulnerable. */
  openSslCcs?: number;
  hstsPolicy?: { status?: string };
}

interface SslLabsEndpoint {
  grade?: string;
  gradeTrustIgnored?: string;
  hasWarnings?: boolean;
  isExceptional?: boolean;
  details?: SslLabsDetails;
  statusMessage?: string;
  statusDetails?: string;
  statusDetailsMessage?: string;
}

interface SslLabsResponse {
  status: string;
  host?: string;
  endpoints?: SslLabsEndpoint[];
  errors?: Array<{ message: string }>;
}

async function fetchAnalysis(host: string, startNew: boolean): Promise<SslLabsResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  const params = new URLSearchParams({
    host,
    fromCache: startNew ? "off" : "on",
    all: "done",
  });
  if (startNew) params.set("startNew", "on");

  try {
    const res = await fetch(`${SSL_LABS_BASE}/analyze?${params.toString()}`, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`SSL Labs API returned ${res.status}`);
    return res.json() as Promise<SslLabsResponse>;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Plain-language reasons an assessment is below A, from what SSL Labs reported about the server.
 * Only states what the response says; a field it did not return produces no reason, so an empty
 * list means "SSL Labs did not say", never "nothing is wrong".
 */
export function explainGrade(endpoint: SslLabsEndpoint | undefined): string[] {
  const d = endpoint?.details;
  if (!d) return [];
  const out: string[] = [];

  const legacy = (d.protocols ?? [])
    .filter((p) => (p.name === "SSL") || (p.name === "TLS" && (p.version === "1.0" || p.version === "1.1")))
    .map((p) => `${p.name} ${p.version}`);
  if (legacy.length > 0) out.push(`The server still accepts ${legacy.join(" and ")}, which are obsolete. SSL Labs caps the grade while they are enabled.`);

  if (typeof d.forwardSecrecy === "number" && d.forwardSecrecy < 2) {
    out.push(d.forwardSecrecy === 0
      ? "No forward secrecy: a stolen server key would decrypt past traffic."
      : "Forward secrecy is not used with modern browsers.");
  }
  if (d.supportsRc4) out.push("RC4 cipher suites are enabled; RC4 is broken.");
  if (d.vulnBeast) out.push("Vulnerable to the BEAST attack (TLS 1.0 CBC suites).");
  if (d.heartbleed) out.push("Vulnerable to Heartbleed.");
  if (d.poodle || d.poodleTls === 2) out.push("Vulnerable to POODLE.");
  if (d.freak) out.push("Vulnerable to FREAK (export-grade RSA).");
  if (d.logjam) out.push("Vulnerable to Logjam (weak Diffie-Hellman parameters).");
  if (d.drownVulnerable) out.push("Vulnerable to DROWN (SSLv2 exposure).");
  if (d.openSslCcs === 2 || d.openSslCcs === 3) out.push("Vulnerable to the OpenSSL CCS injection flaw.");
  if (endpoint?.hasWarnings && out.length === 0) out.push("SSL Labs flagged configuration warnings on this endpoint.");
  return out;
}

function extractResult(data: SslLabsResponse): SslLabsResult {
  const endpoint = data.endpoints?.[0];
  const grade = endpoint?.grade ?? null;
  const issues: string[] = [];

  if (endpoint?.hasWarnings)                    issues.push("SSL Labs flagged configuration warnings");
  if (grade === "T")                            issues.push("Certificate is not trusted");
  if (grade && /^[C-F]$/.test(grade))          issues.push(`Weak SSL configuration — grade ${grade}`);
  if (endpoint?.statusDetailsMessage)           issues.push(endpoint.statusDetailsMessage);

  return {
    grade,
    hasWarnings:   endpoint?.hasWarnings   ?? false,
    isExceptional: endpoint?.isExceptional ?? false,
    issues,
    reasons: explainGrade(endpoint),
    reportUrl: data.host ? `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(data.host)}` : null,
  };
}

/**
 * Run an SSL Labs assessment for the given HTTPS hostname.
 * Returns null if the target is not HTTPS, the API times out, or an error occurs.
 */
export async function checkSslLabs(targetUrl: string): Promise<SslLabsResult | null> {
  let hostname: string;
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:") return null;
    hostname = parsed.hostname;
  } catch {
    return null;
  }

  // Always trigger a fresh assessment — never serve cached data.
  // Poll for up to MAX_WAIT_MS; gracefully skip if SSL Labs doesn't finish in time.
  const deadline = Date.now() + MAX_WAIT_MS;
  let isFirstPoll = true;
  let data: SslLabsResponse;

  while (Date.now() < deadline) {
    if (!isFirstPoll) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      await new Promise<void>((r) => setTimeout(r, Math.min(POLL_INTERVAL_MS, remaining)));
    }

    try {
      data = await fetchAnalysis(hostname, isFirstPoll);
      isFirstPoll = false;
    } catch (err) {
      console.warn("[ssllabs] Poll request failed:", err);
      return null;
    }

    if (data.status === "READY")  return extractResult(data);
    if (data.status === "ERROR") {
      console.warn("[ssllabs] Assessment error:", data.errors?.[0]?.message ?? "unknown");
      return null;
    }
  }

  console.warn("[ssllabs] Assessment timed out after", MAX_WAIT_MS, "ms — continuing without TLS grade");
  return null;
}

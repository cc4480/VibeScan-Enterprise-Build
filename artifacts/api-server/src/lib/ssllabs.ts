/**
 * SSL Labs API integration.
 * Uses the free Qualys SSL Labs API v3 (no key required).
 * Polls until the assessment is READY or times out.
 *
 * Reference: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
 */

const SSL_LABS_BASE = "https://api.ssllabs.com/api/v3";
const POLL_INTERVAL_MS = 15_000;
const MAX_WAIT_MS = 120_000;

export interface SslLabsResult {
  grade: string | null;
  hasWarnings: boolean;
  isExceptional: boolean;
  issues: string[];
}

interface SslLabsEndpoint {
  grade?: string;
  gradeTrustIgnored?: string;
  hasWarnings?: boolean;
  isExceptional?: boolean;
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
  const params = new URLSearchParams({
    host,
    fromCache: startNew ? "off" : "on",
    all: "done",
  });
  if (startNew) {
    params.set("startNew", "on");
  }

  const res = await fetch(`${SSL_LABS_BASE}/analyze?${params.toString()}`, {
    headers: { Accept: "application/json" },
  });

  if (!res.ok) {
    throw new Error(`SSL Labs API returned ${res.status}`);
  }

  return res.json() as Promise<SslLabsResponse>;
}

/**
 * Run an SSL Labs assessment for the given HTTPS hostname.
 * Returns null if the target is not HTTPS or the API times out.
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

  const deadline = Date.now() + MAX_WAIT_MS;
  let isFirstRequest = true;

  while (Date.now() < deadline) {
    let data: SslLabsResponse;
    try {
      data = await fetchAnalysis(hostname, isFirstRequest);
      isFirstRequest = false;
    } catch (err) {
      console.warn("[ssllabs] API request failed:", err);
      return null;
    }

    if (data.status === "ERROR") {
      const msg = data.errors?.[0]?.message ?? "unknown error";
      console.warn("[ssllabs] Assessment error:", msg);
      return null;
    }

    if (data.status === "READY") {
      const endpoint = data.endpoints?.[0];
      const grade = endpoint?.grade ?? null;
      const issues: string[] = [];

      if (endpoint?.hasWarnings) {
        issues.push("SSL Labs flagged configuration warnings");
      }
      if (grade === "T") {
        issues.push("Certificate is not trusted");
      }
      if (grade && /^[C-F]$/.test(grade)) {
        issues.push(`Weak SSL configuration — grade ${grade}`);
      }
      if (endpoint?.statusDetailsMessage) {
        issues.push(endpoint.statusDetailsMessage);
      }

      return {
        grade,
        hasWarnings: endpoint?.hasWarnings ?? false,
        isExceptional: endpoint?.isExceptional ?? false,
        issues,
      };
    }

    await new Promise<void>((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  console.warn("[ssllabs] Assessment timed out after", MAX_WAIT_MS, "ms");
  return null;
}

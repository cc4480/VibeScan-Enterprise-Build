import { customFetch } from "@workspace/api-client-react";

/**
 * Domain-ownership verification. Proving you control a domain is what unlocks
 * active security testing against it — see the server's lib/activeProbeGate.ts.
 */

export interface DomainVerification {
  domain: string;
  verified: boolean;
  verifiedAt: string | null;
  method: "dns" | "well_known" | null;
  token: string;
  dns: { name: string; type: string; value: string };
  wellKnown: { url: string; content: string };
}

export async function listDomainVerifications(): Promise<DomainVerification[]> {
  const res = await customFetch<{ verifications: DomainVerification[] }>("/api/domain-verifications");
  return res.verifications;
}

export async function startDomainVerification(domain: string): Promise<DomainVerification> {
  const res = await customFetch<{ verification: DomainVerification }>("/api/domain-verifications", {
    method: "POST",
    body: JSON.stringify({ domain }),
    headers: { "Content-Type": "application/json" },
  });
  return res.verification;
}

/**
 * Asks the server to look for the DNS record or the well-known file.
 *
 * A challenge that has not been satisfied yet is not an error the user needs
 * protecting from — it is the normal state while DNS propagates — so the 409
 * the server returns is unwrapped into a plain "not yet" plus the server's own
 * explanation, rather than being thrown.
 */
export async function checkDomainVerification(
  domain: string,
): Promise<{ verified: boolean; verification: DomainVerification | null; detail?: string }> {
  try {
    const res = await customFetch<{ verification: DomainVerification }>(
      `/api/domain-verifications/${encodeURIComponent(domain)}/check`,
      { method: "POST" },
    );
    return { verified: res.verification.verified, verification: res.verification };
  } catch (err) {
    const apiErr = err as {
      status?: number;
      data?: { detail?: string; verification?: DomainVerification } | null;
    };
    if (apiErr?.status === 409) {
      return {
        verified: false,
        verification: apiErr.data?.verification ?? null,
        detail: apiErr.data?.detail,
      };
    }
    throw err;
  }
}

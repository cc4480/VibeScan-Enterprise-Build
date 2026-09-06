/**
 * Domain-ownership verification.
 *
 * Gates the scanner's ACTIVE offensive probes — path traversal, reflected XSS
 * and error-based SQLi, GraphQL field fuzzing, BaaS and storage probing, the
 * API endpoint sweep, the rate-limit burst and the out-of-band SSRF collector —
 * so the platform cannot be pointed at an arbitrary third party. Only someone
 * who has proven they control a domain may have exploit payloads fired at it.
 *
 * Passive black-box work (response headers, TLS, cookies, DNS records, CVE
 * matching on version strings, JWT analysis) stays available for any target:
 * it is indistinguishable from an ordinary visit and needs no permission.
 *
 * Two proofs are accepted, and either is sufficient:
 *   - a DNS TXT record at _secscan-challenge.<domain>, which requires control
 *     of the zone; or
 *   - a file at /.well-known/secscan-verification.txt, which requires control
 *     of the web root.
 */
import crypto from "node:crypto";
import * as dns from "node:dns/promises";
import { checkHostname } from "./ssrfGuard";

export function extractDomain(rawUrl: string): string {
  let u = (rawUrl || "").trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return new URL(u).hostname.toLowerCase();
}

export function generateVerificationToken(): string {
  return "secscan-verify-" + crypto.randomBytes(16).toString("hex");
}

export function txtRecordName(domain: string): string {
  return `_secscan-challenge.${domain}`;
}

export const WELL_KNOWN_PATH = "/.well-known/secscan-verification.txt";

/** Checks the DNS TXT record at _secscan-challenge.<domain> for the token. */
export async function checkTxtRecord(domain: string, token: string): Promise<boolean> {
  try {
    const records = await dns.resolveTxt(txtRecordName(domain));
    // A TXT value longer than 255 bytes arrives split into chunks; join before
    // comparing or a token that straddles the boundary never matches.
    return records.some((chunks) => chunks.join("").trim() === token);
  } catch {
    return false;
  }
}

/**
 * Checks for the well-known file on the target host.
 *
 * The hostname is re-checked here rather than trusted from the caller, because
 * this issues a real outbound request and is reachable from a user-supplied
 * domain. Redirects are not followed: a 302 could otherwise route the check to
 * a host that was never validated, and a file served from somewhere else
 * proves nothing about this domain.
 *
 * Note the limit honestly — the hostname is resolved for the check and again
 * by fetch, so a DNS record that changes between the two could still move the
 * request. Closing that needs connection-level IP pinning, which nothing in
 * this codebase does yet; this is no weaker than the scanner's own fetches.
 */
export async function checkWellKnownFile(domain: string, token: string): Promise<boolean> {
  const safe = await checkHostname(domain);
  if (!safe.ok) return false;

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await fetch(`https://${domain}${WELL_KNOWN_PATH}`, {
      redirect: "manual",
      signal: ctl.signal,
    });
    if (!res.ok) return false;
    // Cap the read: a verification file is 40-odd bytes, and this is an
    // attacker-controlled endpoint that would otherwise happily stream forever.
    const body = (await res.text()).slice(0, 1024);
    return body.trim() === token;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * SSRF guard for user-supplied URLs.
 *
 * The scanner fetches whatever URL a caller hands it, from inside our own
 * network. Without a guard that turns the product into an open proxy: anyone
 * can point it at 127.0.0.1, a private RFC 1918 range, or the cloud metadata
 * endpoint (169.254.169.254) and read the response back out of the finished
 * report, whose `evidence` fields quote response headers and bodies verbatim.
 *
 * Two callers, two protocol rules:
 *   - scan targets     — http: and https: (a plaintext target is itself a finding)
 *   - outbound webhooks — https: only (see webhook.ts; a token must not go out
 *                         in cleartext)
 * so the protocol check stays with each caller and this module only decides
 * whether a host is safe to talk to.
 *
 * Known residual risk: this validates the address a hostname resolves to at
 * check time, not the address the socket ultimately connects to. A DNS record
 * that changes between the two (classic DNS rebinding) is not covered —
 * closing that needs connection-level pinning of the resolved IP.
 */

import * as net from "node:net";
import * as dns from "node:dns/promises";

export const PRIVATE_IP_PATTERNS = [
  /^127\./, // loopback
  /^0\./, // "this network" — 0.0.0.0/8, reaches loopback on some stacks
  /^10\./, // RFC 1918
  /^172\.(1[6-9]|2\d|3[01])\./, // RFC 1918
  /^192\.168\./, // RFC 1918
  /^169\.254\./, // link-local / AWS + Azure IMDS
  /^100\.6[4-9]\.|^100\.[7-9]\d\.|^100\.1[01]\d\.|^100\.12[0-7]\./, // CGNAT
  /^192\.0\.0\./, // IETF protocol assignments
  /^198\.1[89]\./, // benchmarking
  /^::1$/, // IPv6 loopback
  /^::$/, // IPv6 unspecified
  /^fc[0-9a-f]{2}:/i, // IPv6 unique-local
  /^fd[0-9a-f]{2}:/i, // IPv6 unique-local
  /^fe80:/i, // IPv6 link-local
  /^::ffff:/i, // IPv4-mapped IPv6 — unwrapped below before the v4 checks
];

export const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "169.254.169.254",
  "metadata.internal",
  "metadata",
]);

/** IPv4-mapped IPv6 (::ffff:127.0.0.1) must be tested as the IPv4 address it wraps. */
function unwrapMappedIpv4(ip: string): string {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return m ? m[1]! : ip;
}

export function isPrivateAddress(ip: string): boolean {
  const addr = unwrapMappedIpv4(ip.toLowerCase());
  return PRIVATE_IP_PATTERNS.some((r) => r.test(addr));
}

/**
 * Cheap pre-check: blocked names and literal private IPs, no DNS round-trip.
 * Returns true only if the host is *not* obviously internal.
 */
export function isHostnameSafeSync(hostname: string): boolean {
  if (!hostname) return false;
  if (BLOCKED_HOSTNAMES.has(hostname)) return false;
  if (hostname.endsWith(".local") || hostname.endsWith(".internal")) return false;
  if (net.isIP(hostname)) return !isPrivateAddress(hostname);
  return true;
}

export interface HostCheckResult {
  safe: boolean;
  /** Set when safe === false; safe to show a user, names no internal detail beyond the host they supplied. */
  reason?: string;
}

/**
 * Full check: blocked names, literal private IPs, and public hostnames whose
 * A/AAAA records point somewhere internal. Fails closed on DNS failure.
 */
export async function checkHostname(rawHostname: string): Promise<HostCheckResult> {
  // URL.hostname keeps the brackets on an IPv6 literal ("[::1]"); strip them so
  // net.isIP recognises it, otherwise it falls through to DNS and is blocked
  // only by the fail-closed path, with a misleading "could not resolve" reason.
  const hostname = rawHostname
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[(.+)\]$/, "$1");

  if (!isHostnameSafeSync(hostname)) {
    return {
      safe: false,
      reason: "Target resolves to a private, loopback, or link-local address.",
    };
  }

  if (net.isIP(hostname)) return { safe: true };

  let addresses: string[];
  try {
    addresses = await dns.resolve(hostname);
  } catch {
    return { safe: false, reason: `Could not resolve host "${hostname}".` };
  }

  if (addresses.length === 0) {
    return { safe: false, reason: `Could not resolve host "${hostname}".` };
  }

  for (const addr of addresses) {
    if (isPrivateAddress(addr) || BLOCKED_HOSTNAMES.has(addr)) {
      return {
        safe: false,
        reason: "Target resolves to a private, loopback, or link-local address.",
      };
    }
  }

  return { safe: true };
}

/**
 * Validate a scan target. Accepts http: and https: only, and requires the host
 * to be publicly routable.
 */
export async function checkScanTarget(rawUrl: string): Promise<HostCheckResult> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { safe: false, reason: "Invalid URL." };
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    return { safe: false, reason: "Invalid URL. Must start with http:// or https://" };
  }

  return checkHostname(url.hostname);
}

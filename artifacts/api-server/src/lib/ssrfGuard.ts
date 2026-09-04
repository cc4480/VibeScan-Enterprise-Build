/**
 * Address safety for anything the user gets to point us at.
 *
 * Two callers, two policies, one set of rules:
 *
 *   - webhook.ts sends *our* payloads to a URL the user configured, so it also
 *     insists on https.
 *   - the scanner fetches a target the user asked us to scan, where plaintext
 *     http is legitimate — "no HTTPS" is one of the findings we report.
 *
 * What they share is the part that matters: never open a connection to an
 * address that belongs to the machine or the network we are running on. A
 * scanner is an unusually attractive SSRF primitive — it takes a URL from a
 * stranger, fetches it, follows redirects, scans ports, and hands the results
 * back — so the check runs on every hop, not just on the URL first submitted.
 *
 * Self-hosted operators scanning their own internal estate are a real use case
 * and the reason ALLOW_PRIVATE_SCAN_TARGETS exists. It is deliberately not on
 * by default: the safe configuration is the one you get by doing nothing.
 */

import * as net from "node:net";
import * as dns from "node:dns/promises";

export const PRIVATE_IP_PATTERNS = [
  /^127\./,           // loopback
  /^0\./,             // "this network" — 0.0.0.0/8, reaches localhost on Linux
  /^10\./,            // RFC 1918
  /^172\.(1[6-9]|2\d|3[01])\./,  // RFC 1918
  /^192\.168\./,      // RFC 1918
  /^169\.254\./,      // link-local — AWS/Azure/GCP instance metadata
  /^100\.6[4-9]\.|^100\.[7-9]\d\.|^100\.1[01]\d\.|^100\.12[0-7]\./,  // CGNAT
  /^192\.0\.0\./,     // IETF protocol assignments
  /^198\.1[89]\./,    // benchmarking
  /^::1$/,            // IPv6 loopback
  /^::$/,             // IPv6 unspecified
  /^fc[0-9a-f]{2}:/i, // IPv6 unique-local
  /^fd[0-9a-f]{2}:/i,
  /^fe[89ab][0-9a-f]:/i, // IPv6 link-local
  /^::ffff:/i,        // IPv4-mapped IPv6 — unwrapped below before testing
];

export const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "169.254.169.254",
  "metadata.internal",
  "metadata",
]);

/** Suffixes that only ever name something inside the local network. */
const BLOCKED_SUFFIXES = [".local", ".internal", ".localhost", ".home.arpa"];

/**
 * True when this address is one we must never connect to on a user's say-so.
 *
 * IPv4-mapped IPv6 (::ffff:127.0.0.1) is unwrapped first: it is the same
 * destination written a second way, and matching only the textual form would
 * let it through.
 */
export function isPrivateAddress(addr: string): boolean {
  const normalized = addr.toLowerCase().replace(/^\[|\]$/g, "");
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(normalized);
  const candidate = mapped?.[1] ?? normalized;
  return PRIVATE_IP_PATTERNS.some((r) => r.test(candidate));
}

/**
 * Cheap pre-check: blocked names and literal private IPs, decided without a DNS
 * round-trip. Returns false only when the hostname is definitively unsafe — a
 * true here still needs resolvesPublicly() for anything that is not an IP.
 */
export function isHostnameSafeSync(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!host) return false;
  if (BLOCKED_HOSTNAMES.has(host)) return false;
  if (BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) return false;
  // A bare label with no dot ("intranet", "db") is a local network name.
  if (!host.includes(".") && !net.isIP(host)) return false;
  if (net.isIP(host)) return !isPrivateAddress(host);
  return true;
}

// Resolution is cached because the scanner asks about the same host on every
// request of a scan, and a DNS round-trip per request would dominate the time
// budget. The TTL is short enough that a rebinding attack has to win a race
// rather than simply wait us out.
const RESOLVE_TTL_MS = 30_000;
const RESOLVE_CACHE_MAX = 512;
const resolveCache = new Map<string, { safe: boolean; at: number }>();

/** Test seam — the scanner never calls this. */
export function _clearResolveCache(): void {
  resolveCache.clear();
}

/**
 * Resolve a hostname and confirm every address it answers with is public.
 *
 * Fails closed: a name we cannot resolve is a name we will not fetch. Any
 * single private answer blocks the host, because a round-robin record that
 * returns one public and one private address is the classic bypass.
 */
export async function resolvesPublicly(hostname: string): Promise<boolean> {
  const host = hostname.toLowerCase().replace(/\.$/, "");

  const hit = resolveCache.get(host);
  if (hit && Date.now() - hit.at < RESOLVE_TTL_MS) return hit.safe;

  let safe: boolean;
  try {
    const results = await dns.lookup(host, { all: true, verbatim: true });
    safe = results.length > 0 && !results.some((r) => isPrivateAddress(r.address));
  } catch {
    safe = false;
  }

  if (resolveCache.size >= RESOLVE_CACHE_MAX) {
    // Cheap eviction: the oldest inserted key. A strict LRU is not worth the
    // bookkeeping for a cache this size.
    const oldest = resolveCache.keys().next().value;
    if (oldest !== undefined) resolveCache.delete(oldest);
  }
  resolveCache.set(host, { safe, at: Date.now() });
  return safe;
}

/** True when the operator has opted into scanning their own internal network. */
export function privateTargetsAllowed(): boolean {
  return process.env["ALLOW_PRIVATE_SCAN_TARGETS"] === "true";
}

export interface UrlCheck {
  ok: boolean;
  /** Present when ok is false. Safe to show a user: names no internal address. */
  reason?: string;
}

/**
 * The full check. `requireHttps` is for callers that send data outward;
 * `allowOptOut` is for the scan path, which a self-hosted operator may point at
 * their own network on purpose.
 */
export async function checkUrlSafe(
  rawUrl: string,
  opts: { requireHttps?: boolean; allowOptOut?: boolean } = {},
): Promise<UrlCheck> {
  const { requireHttps = false, allowOptOut = false } = opts;

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "not a valid URL" };
  }

  if (requireHttps) {
    if (url.protocol !== "https:") return { ok: false, reason: "must use https" };
  } else if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: "must use http or https" };
  }

  if (allowOptOut && privateTargetsAllowed()) return { ok: true };

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");

  if (!isHostnameSafeSync(hostname)) {
    return { ok: false, reason: "resolves to a private or local address" };
  }

  if (!net.isIP(hostname) && !(await resolvesPublicly(hostname))) {
    return { ok: false, reason: "resolves to a private or local address" };
  }

  return { ok: true };
}

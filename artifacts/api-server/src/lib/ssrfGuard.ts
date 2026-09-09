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
  // An address that embeds an IPv4 one is judged on the IPv4 it carries,
  // whatever notation it arrives in. The `^::ffff:` entry in the pattern list
  // already catches the common mapped forms outright, but two others reach
  // here intact, and Node's URL parser is what produces them:
  //   [::127.0.0.1]      -> ::7f00:1        (deprecated IPv4-compatible)
  //   [64:ff9b::7f00:1]  -> unchanged       (NAT64 well-known prefix)
  // Neither is routable in most networks — the compatible form is deprecated
  // and NAT64 needs a translating gateway — so this is defence in depth rather
  // than a live hole. The sibling scanner had the fully exploitable version of
  // this, where hex mapped forms walked straight past the guard.
  const embedded = embeddedIpv4(normalized);
  if (embedded) return isPrivateAddress(embedded);
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(normalized);
  const candidate = mapped?.[1] ?? normalized;
  return PRIVATE_IP_PATTERNS.some((r) => r.test(candidate));
}

/**
 * The IPv4 address embedded in an IPv6 address, dotted, or null.
 *
 * Handles IPv4-mapped (::ffff:0:0/96), the deprecated IPv4-compatible form
 * (::/96) and NAT64's well-known prefix (64:ff9b::/96), from the fully expanded
 * address so notation does not matter.
 */
function embeddedIpv4(addr: string): string | null {
  if (!net.isIPv6(addr)) return null;
  let text = addr.replace(/%.*$/, "");
  let tail: number[] = [];
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (dotted) {
    const o = dotted[1].split(".").map(Number);
    if (o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    tail = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    text = text.slice(0, -dotted[1].length).replace(/:$/, "") + ":";
    if (text === ":") text = "::";
  }
  const [head, rest, extra] = text.split("::");
  if (extra !== undefined) return null;
  const parse = (part: string) => part.split(":").filter(Boolean).map((h) => parseInt(h, 16));
  const left = parse(head ?? "");
  const right = rest === undefined ? [] : parse(rest);
  const groups =
    rest === undefined
      ? [...left, ...tail]
      : [
          ...left,
          ...new Array(Math.max(0, 8 - left.length - right.length - tail.length)).fill(0),
          ...right,
          ...tail,
        ];
  if (groups.length !== 8 || groups.some((g) => !Number.isInteger(g) || g < 0 || g > 0xffff)) return null;
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
  const dot = () => `${(g6 >> 8) & 0xff}.${g6 & 0xff}.${(g7 >> 8) & 0xff}.${g7 & 0xff}`;
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) return dot();
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) return dot();
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && (g6 !== 0 || g7 > 1)) return dot();
  return null;
}

/**
 * Cheap pre-check: blocked names and literal private IPs, decided without a DNS
 * round-trip. Returns false only when the hostname is definitively unsafe — a
 * true here still needs resolvesPublicly() for anything that is not an IP.
 */
export function isHostnameSafeSync(hostname: string): boolean {
  // URL.hostname keeps the brackets on an IPv6 literal ("[::1]"), which
  // net.isIP does not recognise. Without stripping them, every IPv6-literal
  // target — including perfectly public ones — fell through to the bare-label
  // rule below and was refused.
  const host = hostname
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[(.+)\]$/, "$1");
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

  const hostname = url.hostname
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[(.+)\]$/, "$1");

  if (!isHostnameSafeSync(hostname)) {
    return { ok: false, reason: "resolves to a private or local address" };
  }

  if (!net.isIP(hostname) && !(await resolvesPublicly(hostname))) {
    return { ok: false, reason: "resolves to a private or local address" };
  }

  return { ok: true };
}

/**
 * Validate a scan target: http/https only, host publicly routable.
 *
 * Kept as a named entry point because it reads better at the call site than
 * checkUrlSafe with options, and because it is the shape the route already
 * used before the two implementations of this module were reconciled.
 */
export async function checkScanTarget(rawUrl: string): Promise<UrlCheck> {
  return checkUrlSafe(rawUrl, { allowOptOut: true });
}

/**
 * Hostname-only check, for callers that have already dealt with the scheme.
 *
 * webhook.ts enforces https itself (a token must not go out in cleartext) and
 * only needs to know whether the host is safe to talk to.
 */
export async function checkHostname(rawHostname: string): Promise<UrlCheck> {
  const host = rawHostname
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[(.+)\]$/, "$1");

  if (!isHostnameSafeSync(host)) {
    return { ok: false, reason: "resolves to a private or local address" };
  }
  if (!net.isIP(host) && !(await resolvesPublicly(host))) {
    return { ok: false, reason: "resolves to a private or local address" };
  }
  return { ok: true };
}

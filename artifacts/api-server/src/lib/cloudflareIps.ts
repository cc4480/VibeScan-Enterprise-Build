/**
 * Is this address one of Cloudflare's edge servers?
 *
 * This exists to answer a question the app cannot otherwise answer on a managed
 * platform: did this request actually come through Cloudflare, or did someone
 * send it straight to the origin?
 *
 * On a server you own, the origin is firewalled to Cloudflare's ranges and the
 * question is settled by the firewall. Railway, Fly and Render all keep a public
 * hostname that cannot be closed off, so the app has to decide for itself.
 *
 * The trick is that the request chain is:
 *
 *     client → Cloudflare → Railway's router → this process
 *
 * and each hop appends the address it saw to X-Forwarded-For. So the *last*
 * entry is the address Railway's router observed — the Cloudflare edge, for a
 * proxied request. A client cannot forge that position: it can prepend whatever
 * it likes to X-Forwarded-For, but the final entry is written by Railway, after
 * the client's bytes have stopped mattering.
 *
 * Checking that entry against Cloudflare's published ranges therefore tells us
 * whether Cloudflare really was in front, without a shared secret, without a
 * Transform Rule, and without anything to rotate. It also degrades safely: an
 * unrecognised address simply means "not proxied", and the caller falls back to
 * a source it can trust.
 *
 * The bundled list is refreshed at runtime because Cloudflare does change it —
 * rarely, but it does. A failed refresh leaves the bundled list in place rather
 * than emptying it, because an empty list would silently classify every request
 * as un-proxied.
 */

import * as net from "node:net";
import { logger } from "./logger";

/**
 * Fetched from https://www.cloudflare.com/ips-v4 and /ips-v6 on 4 September
 * 2026. Refreshed at runtime; this is the floor, not the source of truth.
 */
const BUNDLED_V4 = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
];

const BUNDLED_V6 = [
  "2400:cb00::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2405:b500::/32",
  "2405:8100::/32",
  "2a06:98c0::/29",
  "2c0f:f248::/32",
];

interface Range4 {
  base: number;
  mask: number;
}
interface Range6 {
  base: bigint;
  bits: number;
}

function parseV4(cidr: string): Range4 | null {
  const [addr, lenRaw] = cidr.split("/");
  if (!addr || !lenRaw) return null;
  const len = Number(lenRaw);
  if (!Number.isInteger(len) || len < 0 || len > 32) return null;
  const n = v4ToInt(addr);
  if (n === null) return null;
  // A /0 mask has to be 0, and `-1 << 32` is not that in 32-bit arithmetic.
  const mask = len === 0 ? 0 : (-1 << (32 - len)) >>> 0;
  return { base: (n & mask) >>> 0, mask };
}

function v4ToInt(addr: string): number | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const b = Number(p);
    if (b > 255) return null;
    n = (n << 8) | b;
  }
  return n >>> 0;
}

/** Expands an IPv6 address (including :: and IPv4-mapped forms) to a BigInt. */
function v6ToBigInt(addr: string): bigint | null {
  let a = addr.trim().toLowerCase().replace(/^\[|\]$/g, "");
  // Strip a zone index; it is meaningless here.
  const pct = a.indexOf("%");
  if (pct !== -1) a = a.slice(0, pct);

  // An embedded IPv4 tail (::ffff:1.2.3.4) becomes two hex groups.
  const v4tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (v4tail?.[1]) {
    const n = v4ToInt(v4tail[1]);
    if (n === null) return null;
    const hi = ((n >>> 16) & 0xffff).toString(16);
    const lo = (n & 0xffff).toString(16);
    a = a.slice(0, v4tail.index) + `${hi}:${lo}`;
  }

  const dbl = a.indexOf("::");
  let groups: string[];
  if (dbl === -1) {
    groups = a.split(":");
    if (groups.length !== 8) return null;
  } else {
    const head = a.slice(0, dbl).split(":").filter((g) => g !== "");
    const tail = a.slice(dbl + 2).split(":").filter((g) => g !== "");
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill("0"), ...tail];
  }

  let out = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out = (out << 16n) | BigInt(parseInt(g, 16));
  }
  return out;
}

function parseV6(cidr: string): Range6 | null {
  const [addr, lenRaw] = cidr.split("/");
  if (!addr || !lenRaw) return null;
  const bits = Number(lenRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null;
  const n = v6ToBigInt(addr);
  if (n === null) return null;
  const shift = BigInt(128 - bits);
  return { base: (n >> shift) << shift, bits };
}

let ranges4: Range4[] = BUNDLED_V4.map(parseV4).filter((r): r is Range4 => r !== null);
let ranges6: Range6[] = BUNDLED_V6.map(parseV6).filter((r): r is Range6 => r !== null);

/** True when `addr` falls inside any known Cloudflare range. */
export function isCloudflareIp(addr: string): boolean {
  const cleaned = addr.trim().replace(/^\[|\]$/g, "");
  if (!cleaned) return false;

  const kind = net.isIP(cleaned);

  if (kind === 4) {
    const n = v4ToInt(cleaned);
    if (n === null) return false;
    return ranges4.some((r) => ((n & r.mask) >>> 0) === r.base);
  }

  if (kind === 6) {
    // An IPv4-mapped address is an IPv4 address written differently; judge it
    // against the v4 ranges rather than reporting "not Cloudflare".
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(cleaned);
    if (mapped?.[1]) return isCloudflareIp(mapped[1]);

    const n = v6ToBigInt(cleaned);
    if (n === null) return false;
    return ranges6.some((r) => {
      const shift = BigInt(128 - r.bits);
      return (n >> shift) << shift === r.base;
    });
  }

  return false;
}

/**
 * Replaces the in-memory list from Cloudflare's published endpoints.
 *
 * Deliberately all-or-nothing per family: a partial or empty answer keeps the
 * previous list, because shrinking this list turns proxied requests into
 * apparently-direct ones and quietly disables the protection it exists for.
 */
export async function refreshCloudflareIps(): Promise<boolean> {
  try {
    const [v4res, v6res] = await Promise.all([
      fetch("https://www.cloudflare.com/ips-v4", { signal: AbortSignal.timeout(10_000) }),
      fetch("https://www.cloudflare.com/ips-v6", { signal: AbortSignal.timeout(10_000) }),
    ]);
    if (!v4res.ok || !v6res.ok) throw new Error(`http ${v4res.status}/${v6res.status}`);

    const parse = (text: string) =>
      text.split("\n").map((l) => l.trim()).filter((l) => l.includes("/"));

    const got4 = parse(await v4res.text());
    const got6 = parse(await v6res.text());

    // Sanity floor: the published set has been ~15 and ~7 for years. A much
    // shorter answer means something served us a partial or error page.
    if (got4.length < 10 || got6.length < 5) {
      throw new Error(`implausible list sizes: ${got4.length}/${got6.length}`);
    }

    const parsed4 = got4.map(parseV4).filter((r): r is Range4 => r !== null);
    const parsed6 = got6.map(parseV6).filter((r): r is Range6 => r !== null);
    if (parsed4.length !== got4.length || parsed6.length !== got6.length) {
      throw new Error("unparseable entries in published list");
    }

    ranges4 = parsed4;
    ranges6 = parsed6;
    logger.info(
      { v4: parsed4.length, v6: parsed6.length },
      "Cloudflare IP ranges refreshed",
    );
    return true;
  } catch (err) {
    logger.warn({ err }, "Could not refresh Cloudflare IP ranges — keeping current list");
    return false;
  }
}

/** Test seam: restores the bundled list. */
export function _resetCloudflareIps(): void {
  ranges4 = BUNDLED_V4.map(parseV4).filter((r): r is Range4 => r !== null);
  ranges6 = BUNDLED_V6.map(parseV6).filter((r): r is Range6 => r !== null);
}

export function _rangeCounts(): { v4: number; v6: number } {
  return { v4: ranges4.length, v6: ranges6.length };
}

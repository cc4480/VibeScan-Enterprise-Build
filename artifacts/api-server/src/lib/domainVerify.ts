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
 *
 * A verification is not permanent. It stays valid for VERIFICATION_VALID_DAYS
 * after the last time the proof was seen, and lib/domainReverify.ts (a daily
 * job) looks for the proof again and moves that date forward while it is still
 * there. A domain that was sold or abandoned therefore stops being attackable
 * by its previous owner once the proof is gone.
 */
import crypto from "node:crypto";
import * as dns from "node:dns/promises";
import { checkHostname, isPrivateAddress } from "./ssrfGuard";
import { strictDispatcher } from "./pinnedDispatcher";
import { readBodyMarked } from "./httpBody";

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

/**
 * How long a verification stays valid after the proof was last seen. Long
 * enough that a few days of DNS or hosting trouble does not lock a user out of
 * their own domain (the daily re-check just keeps failing, and the row lapses
 * only after a fortnight of it); short enough that a domain which changed hands
 * does not stay open to its previous owner.
 */
export const VERIFICATION_VALID_DAYS = 14;
const DAY_MS = 86_400_000;

/** A verification whose `verifiedAt` is later than this is still valid. */
export function verificationCutoff(now: Date = new Date()): Date {
  return new Date(now.getTime() - VERIFICATION_VALID_DAYS * DAY_MS);
}

/** When a verification last proved at `verifiedAt` lapses unless the proof is seen again. */
export function verificationExpiresAt(verifiedAt: Date): Date {
  return new Date(verifiedAt.getTime() + VERIFICATION_VALID_DAYS * DAY_MS);
}

/**
 * The same boundary the active-probe gate applies in SQL (strictly later than
 * the cutoff), for code that already holds the row.
 */
export function isVerificationCurrent(verifiedAt: Date | null | undefined, now: Date = new Date()): boolean {
  return verifiedAt != null && verifiedAt.getTime() > verificationCutoff(now).getTime();
}

// A TXT value longer than 255 bytes arrives split into chunks; join before
// comparing or a token that straddles the boundary never matches.
const hasToken = (records: string[][], token: string) =>
  records.some((chunks) => chunks.join("").trim() === token);

/**
 * The zone's own nameservers, as public IPv4 addresses. Walks up from the
 * name until a zone apex answers NS (a subdomain like app.example.com usually
 * has none of its own).
 */
async function authoritativeServers(domain: string): Promise<string[]> {
  const labels = domain.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const zone = labels.slice(i).join(".");
    let ns: string[];
    try {
      ns = await dns.resolveNs(zone);
    } catch {
      continue;
    }
    const ips = (await Promise.all(ns.slice(0, 4).map((h) => dns.resolve4(h).catch(() => [] as string[])))).flat();
    // The NS names come from the user's zone; never aim a query at a private
    // address because a zone says to.
    return ips.filter((ip) => !isPrivateAddress(ip));
  }
  return [];
}

/**
 * Longest the direct-to-authority attempt may take, in total. It is an optimisation (it dodges a stale
 * negative-cache answer), so it must never decide how long a check takes: a platform that blocks
 * outbound DNS to arbitrary nameservers would otherwise spend 15 s or more here, per domain, before the
 * fallback and the HTTPS check even start. On the first scheduled re-verification in production every
 * check ran into the 30 s backstop for that reason.
 */
export const AUTHORITY_DEADLINE_MS = 6_000;

/** Asks the zone's nameservers directly. They hold the zone, so no cache sits in between. */
async function txtFromAuthority(name: string, domain: string, held: { resolver?: dns.Resolver }): Promise<string[][] | null> {
  const servers = await authoritativeServers(domain);
  if (servers.length === 0) return null;
  // One try per server and a short wait: a nameserver that is going to answer does so in milliseconds.
  const resolver = new dns.Resolver({ timeout: 2000, tries: 1 });
  held.resolver = resolver;
  resolver.setServers(servers);
  try {
    return await resolver.resolveTxt(name);
  } catch (err) {
    // "No such record" from the authority is a real answer; anything else
    // (timeout, refused, cancelled) means we could not ask and should fall back.
    const code = (err as NodeJS.ErrnoException).code;
    return code === "ENOTFOUND" || code === "ENODATA" ? [] : null;
  }
}

/** txtFromAuthority, abandoned (and its outstanding queries cancelled) after AUTHORITY_DEADLINE_MS. */
async function txtFromAuthorityWithinDeadline(name: string, domain: string): Promise<string[][] | null> {
  const held: { resolver?: dns.Resolver } = {};
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<null>((resolve) => {
    timer = setTimeout(() => {
      held.resolver?.cancel();
      resolve(null);
    }, AUTHORITY_DEADLINE_MS);
  });
  try {
    return await Promise.race([txtFromAuthority(name, domain, held), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Checks the DNS TXT record at _secscan-challenge.<domain> for the token.
 *
 * The zone's authoritative nameservers are asked first. Going through the
 * host's recursive resolver alone made verification fail for minutes after a
 * record was added: a check that ran before the record existed cached "no
 * such name" for the zone's negative TTL (1800 s on Cloudflare), and the user
 * had to press Check over and over until a query happened to land on a
 * resolver without the stale answer. The recursive resolver stays as a
 * fallback for networks that cannot reach the authority directly.
 */
export async function checkTxtRecord(domain: string, token: string): Promise<boolean> {
  const name = txtRecordName(domain);
  try {
    const fresh = await txtFromAuthorityWithinDeadline(name, domain);
    if (fresh && hasToken(fresh, token)) return true;
  } catch {
    // fall through to the recursive resolver
  }
  try {
    return hasToken(await dns.resolveTxt(name), token);
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
 * The hostname is resolved for the check and again to connect, so the request
 * goes through strictDispatcher, which vets the address the socket opens to.
 */
export async function checkWellKnownFile(domain: string, token: string): Promise<boolean> {
  const safe = await checkHostname(domain);
  if (!safe.ok) return false;

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 5000);
  try {
    // Cache-busted: a CDN in front of the site (Cloudflare caches .txt) may
    // still hold the 404 from a check made before the file was deployed.
    const res = await fetch(`https://${domain}${WELL_KNOWN_PATH}?check=${Date.now()}`, {
      redirect: "manual",
      signal: ctl.signal,
      headers: { "Cache-Control": "no-cache" },
      dispatcher: strictDispatcher,
    } as RequestInit);
    if (!res.ok) return false;
    // Cap the read: a verification file is 40-odd bytes, and this is an
    // attacker-controlled endpoint that would otherwise happily stream forever.
    // readBodyMarked stops reading at the cap; res.text() would pull the whole stream first.
    const { body } = await readBodyMarked(res, 1024);
    return body.trim() === token;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export type VerificationMethod = "dns" | "well_known";

/**
 * The one check for "is the proof for this token live right now". Used by the
 * user-triggered check endpoint and by the scheduled re-verification, so the
 * two cannot drift apart: whatever passes the first is exactly what keeps a
 * domain verified afterwards.
 *
 * DNS first: it is cheaper than an HTTP round trip and cannot be satisfied by
 * anyone who merely controls a path on the web server.
 */
export async function runVerificationCheck(domain: string, token: string): Promise<VerificationMethod | null> {
  if (await checkTxtRecord(domain, token)) return "dns";
  if (await checkWellKnownFile(domain, token)) return "well_known";
  return null;
}

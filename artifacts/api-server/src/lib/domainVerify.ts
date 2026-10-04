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
import { checkHostname, isPrivateAddress } from "./ssrfGuard";
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

/** Asks the zone's nameservers directly. They hold the zone, so no cache sits in between. */
async function txtFromAuthority(name: string, domain: string): Promise<string[][] | null> {
  const servers = await authoritativeServers(domain);
  if (servers.length === 0) return null;
  const resolver = new dns.Resolver({ timeout: 3000, tries: 2 });
  resolver.setServers(servers);
  try {
    return await resolver.resolveTxt(name);
  } catch (err) {
    // "No such record" from the authority is a real answer; anything else
    // (timeout, refused) means we could not ask and should fall back.
    const code = (err as NodeJS.ErrnoException).code;
    return code === "ENOTFOUND" || code === "ENODATA" ? [] : null;
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
    const fresh = await txtFromAuthority(name, domain);
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
    // Cache-busted: a CDN in front of the site (Cloudflare caches .txt) may
    // still hold the 404 from a check made before the file was deployed.
    const res = await fetch(`https://${domain}${WELL_KNOWN_PATH}?check=${Date.now()}`, {
      redirect: "manual",
      signal: ctl.signal,
      headers: { "Cache-Control": "no-cache" },
    });
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

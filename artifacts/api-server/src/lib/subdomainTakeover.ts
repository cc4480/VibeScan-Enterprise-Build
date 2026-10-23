/**
 * Subdomain takeover detection.
 *
 * Resolves the target hostname's CNAME chain via Cloudflare DNS-over-HTTPS,
 * checks whether the final CNAME points to a known cloud service, then
 * fetches that target to verify it returns an "unclaimed resource" fingerprint.
 *
 * Covers: AWS S3, Heroku, GitHub Pages, Netlify, Vercel, Azure, Fastly,
 * Shopify, Ghost Pro, Surge.sh, Cargo, Readme.io, Pantheon, Squarespace,
 * Tumblr, WP Engine, Fly.io, Render, and Railway.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { dohEndpoint } from "./dnsChecksCore";

const TIMEOUT_MS = 8_000;
/** Provider unclaimed-resource pages are tiny; a large page is a live site. */
const MAX_ERROR_PAGE_CHARS = 20_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─── DNS helpers ──────────────────────────────────────────────────────────────

interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohResponse {
  Status: number;
  Answer?: DnsAnswer[];
}

async function dohQuery(name: string, type: string): Promise<DnsAnswer[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const url = `${dohEndpoint()}?name=${encodeURIComponent(name)}&type=${type}&ct=application/dns-json`;
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    if (!res.ok) return [];
    // Bounded like every other body read; a body that is cut short fails to parse and yields no answers.
    const json = JSON.parse(await readBodyBounded(res)) as DohResponse;
    return json.Answer ?? [];
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/** Follow the CNAME chain up to 5 hops, return final target or null. */
async function resolveCnameChain(hostname: string): Promise<string | null> {
  let current = hostname;
  for (let hop = 0; hop < 5; hop++) {
    const answers = await dohQuery(current, "CNAME");
    const cname = answers.find((a) => a.type === 5); // 5 = CNAME
    if (!cname) return hop === 0 ? null : current; // no further CNAME
    current = cname.data.replace(/\.$/, "");
  }
  return current;
}

// ─── Service fingerprints ─────────────────────────────────────────────────────

import { type ServiceFingerprint, SERVICES } from "./subdomain-service-data";
import { scanFetch } from "./http";
import { readBodyBounded } from "./httpBody";


// ─── HTTP helper ──────────────────────────────────────────────────────────────

async function safeGet(url: string, host?: string): Promise<{ status: number; body: string } | null> {
  // manual: a dangling CNAME is identified by the parked provider's own
  // response, so a redirect must not be followed away from it.
  const res = await scanFetch(url, { redirect: "manual", timeoutMs: TIMEOUT_MS, ...(host ? { headers: { "x-probe-host": host } } : {}) });
  return res ? { status: res.status, body: res.body } : null;
}

// ─── Main export ──────────────────────────────────────────────────────────────

export async function checkSubdomainTakeover(
  targetUrl: string,
): Promise<ScanVulnerability[]> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return [];
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname === "localhost") {
    return [];
  }

  const cname = await resolveCnameChain(hostname);
  if (!cname) return [];

  const service = SERVICES.find((s) => s.cnamePattern.test(cname));
  if (!service) return [];

  // Confirm the unclaimed fingerprint on the ORIGINAL hostname, not the CNAME
  // target. Many providers — Fastly, and CDNs like it — route by Host header:
  // the raw CNAME target (reddit.map.fastly.net) is not itself a configured
  // domain, so requesting it directly returns the provider's "unknown domain"
  // error, which is indistinguishable from a genuinely dangling resource. That
  // fired a Critical takeover on www.reddit.com and every other live
  // Fastly/CDN-fronted site. A real takeover shows the unclaimed fingerprint on
  // the hostname itself — because that is the Host an attacker (and a visitor)
  // would send — while a claimed, working site serves its real page there. So
  // the hostname is the only correct place to look.
  // TAKEOVER_PROBE_ORIGIN sends the same request to one fixed address naming the hostname in an X-Probe-Host header (fetch
  // will not send a Host of its own choosing), which is how tests reach a server of their own; unset, the hostname is fetched itself.
  const via = process.env["TAKEOVER_PROBE_ORIGIN"];
  const result = via
    ? await safeGet(`${via.replace(/\/$/, "")}/`, hostname)
    : ((await safeGet(`https://${hostname}/`)) ?? (await safeGet(`http://${hostname}/`)));

  if (!result) return [];

  // The provider's own unclaimed-resource page is an error response with a short
  // body. A live host that merely CNAMEs to the provider serves 2xx, or a large
  // page in which a fingerprint phrase happens to appear (a Netlify page
  // mentioning "404", a Ghost post quoting the error text).
  if (result.status < 400 || result.body.length > MAX_ERROR_PAGE_CHARS) return [];
  if (!service.bodyFingerprints.some((rx) => rx.test(result.body))) return [];

  const ambiguous = service.ambiguous === true;
  const severity = ambiguous ? "medium" : service.severity;

  return [
    vuln({
      name: `Subdomain Takeover — ${service.name} (${hostname})${ambiguous ? " — Unverified" : ""}`,
      severity,
      category: "DNS Security",
      description: ambiguous
        ? `The hostname ${hostname} has a CNAME pointing to ${cname} (${service.name}) and answers with a bare ${service.name} not-found page (HTTP ${result.status}). That same page is also what a claimed ${service.name} site with no matching route returns, so this may be a dangling record or a live site — verify by checking whether the ${service.name} project still exists and serves this domain. If it does not, an attacker can claim it and serve content under your domain.`
        : `The hostname ${hostname} has a CNAME pointing to ${cname} (${service.name}), but that ${service.name} resource is no longer provisioned. An attacker can register or reclaim it and serve arbitrary content — phishing pages, malware, or credential harvesters — under your trusted domain name. This is fully exploitable with no technical barrier.`,
      evidence: `CNAME chain: ${hostname} → ${cname}\nService: ${service.name}\nHTTP ${result.status} with the provider's unclaimed-resource message${ambiguous ? " (identical to a claimed site's default 404 — verify)" : ""}.`,
      solution: `Immediately either: (1) Remove the dangling CNAME DNS record for ${hostname}, or (2) Reprovision the ${service.name} resource to reclaim ownership. Audit all DNS CNAME records regularly — especially after decommissioning cloud services — to catch dangling entries before attackers do.`,
      cweId: "CWE-350",
      cvssScore: ambiguous ? 5.3 : service.cvssScore,
      wstgId: "WSTG-CONF-10",
      confidence: ambiguous ? 40 : 85,
    }),
  ];
}

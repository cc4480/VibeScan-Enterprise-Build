/** DNS record and subdomain enumeration. */
import * as dns from "node:dns/promises";
import { COMMON_SUBDOMAINS } from "./recon-data";
import { dohEndpoint } from "./dnsChecksCore";
import { type DnsRecord, type SubdomainEntry } from "./reconTypes";

// ─── Constants ────────────────────────────────────────────────────────────────


export const DNS_TIMEOUT_MS = 8_000;

export const SUBDOMAIN_CONCURRENCY = 15;

export const CRT_SH_TIMEOUT_MS = 12_000;

export const SUBDOMAIN_CAP = 100; // max crt.sh results to resolve

// ─── DNS enumeration via Cloudflare DoH ──────────────────────────────────────

export async function dohQuery(
  name: string,
  type: string,
): Promise<Array<{ value: string; ttl: number }>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);
  try {
    const url = `${dohEndpoint()}?name=${encodeURIComponent(name)}&type=${type}&ct=application/dns-json`;
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    if (!res.ok) return [];
    const json = (await res.json()) as {
      Answer?: Array<{ data: string; TTL: number }>;
    };
    return (json.Answer ?? []).map((a) => ({
      value: a.data.replace(/\.$/, ""),
      ttl: a.TTL,
    }));
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

export async function enumerateDns(domain: string): Promise<DnsRecord[]> {
  const queries: Array<{ type: string; name: string }> = [
    { type: "A",    name: domain },
    { type: "AAAA", name: domain },
    { type: "MX",   name: domain },
    { type: "NS",   name: domain },
    { type: "TXT",  name: domain },
    { type: "SOA",  name: domain },
    { type: "CAA",  name: domain },
    { type: "TXT",  name: `_dmarc.${domain}` },
  ];

  const results = await Promise.all(
    queries.map(async ({ type, name }) => {
      const answers = await dohQuery(name, type);
      return answers.map((a) => ({
        type,
        value: name !== domain ? `[${name}] ${a.value}` : a.value,
        ttl: a.ttl,
      }));
    }),
  );

  return results.flat();
}

// ─── Subdomain enumeration ────────────────────────────────────────────────────

export async function fetchSubdomainsFromCrtSh(domain: string): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CRT_SH_TIMEOUT_MS);
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return [];
    const json = (await res.json()) as Array<{ name_value: string }>;
    const seen = new Set<string>();
    for (const entry of json) {
      for (const raw of entry.name_value.split("\n")) {
        const sub = raw.trim().toLowerCase().replace(/^\*\./, "");
        if (sub && sub.endsWith(`.${domain}`) && !seen.has(sub)) {
          seen.add(sub);
        }
      }
    }
    return [...seen];
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

export async function resolveSubdomain(
  sub: string,
): Promise<{ ip: string | null; cname: string | null }> {
  try {
    const addresses = await dns.lookup(sub, { all: true, family: 4 });
    return { ip: (addresses as Array<{ address: string }>)[0]?.address ?? null, cname: null };
  } catch {
    try {
      const result = await dns.resolveCname(sub);
      return { ip: null, cname: (result as string[])[0] ?? null };
    } catch {
      return { ip: null, cname: null };
    }
  }
}

export async function enumerateSubdomains(domain: string): Promise<SubdomainEntry[]> {
  const seen = new Set<string>();
  const entries: SubdomainEntry[] = [];

  const crtShSubs = await fetchSubdomainsFromCrtSh(domain);

  // Build deduplicated task list: crt.sh first, then wordlist for any not already found
  const allTasks: Array<{ sub: string; source: "crt.sh" | "wordlist" }> = [];

  for (const s of crtShSubs.slice(0, SUBDOMAIN_CAP)) {
    if (!seen.has(s)) { seen.add(s); allTasks.push({ sub: s, source: "crt.sh" }); }
  }
  for (const w of COMMON_SUBDOMAINS) {
    const s = `${w}.${domain}`;
    if (!seen.has(s)) { seen.add(s); allTasks.push({ sub: s, source: "wordlist" }); }
  }

  for (let i = 0; i < allTasks.length; i += SUBDOMAIN_CONCURRENCY) {
    const batch = allTasks.slice(i, i + SUBDOMAIN_CONCURRENCY);
    const resolved = await Promise.all(
      batch.map(async ({ sub, source }) => {
        const { ip, cname } = await resolveSubdomain(sub);
        if (!ip && !cname) return null;
        return { subdomain: sub, ip, cname, source } satisfies SubdomainEntry;
      }),
    );
    for (const r of resolved) {
      if (r) entries.push(r);
    }
  }

  return entries;
}

/** DNS-over-HTTPS lookups and domain-chain helpers. */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

/** The DNS-over-HTTPS resolver. DOH_ENDPOINT_URL points it elsewhere (tests run a real resolver on loopback); read per call. */
export function dohEndpoint(): string {
  return process.env["DOH_ENDPOINT_URL"] || "https://cloudflare-dns.com/dns-query";
}

export const DNS_TIMEOUT_MS = 8_000;

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

export interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResponse {
  Status: number;
  Answer?: DnsAnswer[];
}

/**
 * DNS numeric record types, so an answer can be matched against what was asked
 * for. The answer section carries the whole resolution chain, not just the
 * record type in the question: an MX query for a CNAMEd host comes back with
 * the CNAMEs and no MX at all. Counting those as MX records told the SPF check
 * that www.gov.uk "actively sends email", which escalated a finding that was
 * already wrong from Medium to High.
 */
export const RRTYPE = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, DNSKEY: 48 } as const;

/**
 * Returns { answers, status } where:
 *   status  0 = NOERROR  (domain exists, record type may or may not exist)
 *   status  2 = SERVFAIL (resolver error)
 *   status  3 = NXDOMAIN (domain does not exist)
 *   status -1 = network / timeout failure (we don't know)
 *
 * Only report a "missing record" finding when status === 0, so transient
 * failures don't produce false-positive alerts.
 */
export async function dnsQuery(
  name: string,
  type: "TXT" | "MX" | "A" | "DNSKEY" | "NS",
): Promise<{ answers: DnsAnswer[]; status: number }> {
  const first = await dnsQueryOnce(name, type);
  // SERVFAIL is a resolver hiccup, not an answer: nasa.gov's TXT lookup returns it about one time in ten,
  // and one retry nearly always gets the real answer. A second SERVFAIL is passed on as such.
  if (first.status === 2) {
    const second = await dnsQueryOnce(name, type);
    if (second.status !== 2) return second;
  }
  return first;
}

async function dnsQueryOnce(
  name: string,
  type: "TXT" | "MX" | "A" | "DNSKEY" | "NS",
): Promise<{ answers: DnsAnswer[]; status: number }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);
  try {
    const url = `${dohEndpoint()}?name=${encodeURIComponent(name)}&type=${type}&ct=application/dns-json`;
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    if (!res.ok) return { answers: [], status: -1 };
    const json = (await res.json()) as DohResponse;
    const wanted = RRTYPE[type];
    return { answers: (json.Answer ?? []).filter((a) => a.type === wanted), status: json.Status };
  } catch {
    return { answers: [], status: -1 };
  } finally {
    clearTimeout(timer);
  }
}

/** Human-readable DNS status, so evidence states what the resolver actually said. */
export function statusLabel(status: number): string {
  if (status === 0) return "NOERROR (name exists)";
  if (status === 2) return "SERVFAIL (resolver error)";
  if (status === 3) return "NXDOMAIN (name does not exist)";
  return `status ${status}`;
}

/**
 * Every ancestor of a hostname that could hold an organisational record, most
 * specific first, stopping before the bare TLD: www.gov.uk -> www.gov.uk, gov.uk.
 *
 * Walking the chain replaces guessing the registrable domain from label
 * arithmetic. The guess got www.gov.uk wrong — "uk" is two characters and "gov"
 * is three, so it took the .co.uk branch and then returned the hostname
 * unchanged, and SPF was looked up at www.gov.uk while GOV.UK publishes
 * v=spf1 -all at gov.uk. Any record found anywhere up the chain means the
 * organisation has published one, which is the question being asked.
 */
export function ancestorDomains(hostname: string): string[] {
  const labels = hostname.split(".").filter(Boolean);
  const out: string[] = [];
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join("."));
  return out.slice(0, 4);
}

/**
 * Looks for a record matching `match` at `name`, then at each ancestor.
 * Returns the first hit, or the status of the most specific lookup so a caller
 * can tell "no record" from "could not ask".
 *
 * `nxdomainMeansAbsent` decides what NXDOMAIN is evidence of, and the two
 * callers genuinely differ:
 *
 *   DMARC asks for `_dmarc.<domain>`, a label that only exists when a policy
 *   has been published. NXDOMAIN there is the ordinary way of saying "no DMARC
 *   record" — europa.eu answers exactly that — so treating it as unknown loses
 *   a true finding.
 *
 *   SPF asks for the domain itself, which we have just fetched a web page
 *   from. NXDOMAIN there means the lookup failed to describe reality, and a
 *   missing-record finding must not be built on it.
 */
export async function findUpChain(
  hostname: string,
  label: (domain: string) => string,
  match: (txt: string) => boolean,
  nxdomainMeansAbsent = false,
): Promise<{
  found: string | null;
  at: string | null;
  /** What the resolver said for the most specific name — reported verbatim in evidence. */
  status: number;
  /** True when the lookups actually established that no record exists. */
  conclusive: boolean;
  checked: string[];
}> {
  const checked: string[] = [];
  let firstStatus = -1;
  // A lookup that failed (SERVFAIL and the like) up the chain means "could not ask", not "no record":
  // the most specific name can answer cleanly with nothing while the parent, where the record
  // usually lives, errored. Concluding "absent" from that reported nasa.gov as having no SPF record.
  let askFailed = false;
  for (const domain of ancestorDomains(hostname)) {
    const queried = label(domain);
    checked.push(queried);
    const { answers, status } = await dnsQuery(queried, "TXT");
    if (checked.length === 1) firstStatus = status;
    if (status === -1) return { found: null, at: null, status: -1, conclusive: false, checked };
    if (status !== 0 && status !== 3) askFailed = true;
    if (status === 3 && nxdomainMeansAbsent) continue;
    const records = answers.map((a) => a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, ""));
    const hit = records.find(match);
    if (hit) return { found: hit, at: queried, status, conclusive: true, checked };
  }
  const conclusive = !askFailed && (firstStatus === 0 || (nxdomainMeansAbsent && firstStatus === 3));
  return { found: null, at: null, status: firstStatus, conclusive, checked };
}

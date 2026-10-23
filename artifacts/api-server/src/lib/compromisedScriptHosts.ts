/**
 * Pages that load a script from a host tied to the 2024 Polyfill.io supply-chain attack.
 *
 * The domains below are the ones researchers (Sansec, Censys, Snyk, 2024) tied to one operation: polyfill.io was
 * bought by a new owner and began serving code that redirected mobile visitors, and the same operator ran or was linked
 * to bootcdn.net, bootcss.com, staticfile.net, staticfile.org and the other domains listed. A page that still loads
 * from one of them runs whatever that host sends today, so this is High even though the page itself looks normal.
 *
 * Matching is on the script's host only, read from the HTML: no request is made. It is a claim about the host, so a
 * subdomain of a listed domain is flagged, and nothing else is.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

export const COMPROMISED_SCRIPT_HOSTS = [
  "polyfill.io",
  "bootcdn.net",
  "bootcss.com",
  "staticfile.net",
  "staticfile.org",
  "unionadjs.com",
  "xhsbpza.com",
  "macoms.la",
  "newcrbpc.com",
] as const;

/** True when the host is one of the listed domains, or a subdomain of one. */
export function isCompromisedScriptHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return COMPROMISED_SCRIPT_HOSTS.some((d) => h === d || h.endsWith(`.${d}`));
}

/** One finding listing every compromised script the page loads, or none. Reads the HTML only. */
export function compromisedScriptFindings(html: string, baseUrl: string, finalUrl = baseUrl): ScanVulnerability[] {
  const hits: string[] = [];
  const srcRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = srcRegex.exec(html)) !== null) {
    try {
      const u = new URL(m[1]!, baseUrl);
      if (isCompromisedScriptHost(u.hostname) && !hits.includes(u.href)) hits.push(u.href);
    } catch {
      // A malformed src is not a script we can name, so it is not reported.
    }
  }
  if (hits.length === 0) return [];

  return [{
    id: randomUUID(),
    name: "Page Loads a Script From a Host Tied to a Known Supply-Chain Attack",
    severity: "high",
    category: "Supply Chain Security",
    description:
      "The page includes a script from a domain that researchers tied to the 2024 Polyfill.io supply-chain attack. " +
      "Those domains served code that redirected visitors and injected malicious scripts, and the code a host sends can " +
      "change at any time, so the page runs whatever that host sends today. Reports said the payload varied by device and " +
      "time, so a visitor may see nothing unusual while another is redirected.",
    evidence: `GET ${finalUrl}\n${hits.slice(0, 5).map((u) => `<script src="${u}">`).join("\n")}`,
    solution:
      "Remove the script tag now. If the library is a polyfill, use a copy you host yourself, or one from a CDN you trust, " +
      "with an integrity hash. Check the page's history for when the tag was added, and treat visitors' sessions from that time as exposed.",
    cweId: "CWE-829",
    cvssScore: 8.1,
    wstgId: "WSTG-CONF-01",
  }];
}

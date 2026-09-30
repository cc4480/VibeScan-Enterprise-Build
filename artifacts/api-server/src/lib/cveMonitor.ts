/**
 * CVE Monitor — matches newly published or newly analysed CVEs from the NVD
 * (National Vulnerability Database) against the software detected in each
 * monitored site's most recent scan.
 *
 * NVD API v2: https://services.nvd.nist.gov/rest/json/cves/2.0
 * Rate limit: 5 requests / 30 s without an API key, 50 with one (NVD_API_KEY).
 *
 * HOW A MATCH IS DECIDED
 *
 * This used to be a keyword search over each CVE's prose description, with no
 * version check: any new CVE that mentioned "nginx" alerted every nginx site,
 * and "php" appears in the description of thousands of CVEs about unrelated PHP
 * applications ("admin.php in SomeCMS…"). Measured against three real hours of
 * NVD data on 2026-09-24: one CVE mentioned nginx, none affected it.
 *
 * Now a match needs NVD's structured affected-product data (CPE): the CVE must
 * list the product itself as vulnerable, identified by vendor and product
 * (cpe:2.3:a:f5:nginx, not the word "nginx"), and when the scan detected a
 * version, that version must fall inside one of the listed ranges.
 *
 *   version detected, inside a range  → "affected" (the version is in range)
 *   version detected, outside all     → no match (that version is not affected)
 *   no version detected               → "unconfirmed", HIGH/CRITICAL only
 *
 * A CVE NVD has not analysed yet carries no CPE data, so it cannot match. It
 * is not lost: the job queries by LAST-MODIFIED date, so when NVD adds the
 * product data days later the CVE comes back through the window and matches
 * then. Alerts are deduplicated per (subscription, CVE) by the scheduler.
 *
 * Hosting and SaaS platforms (Cloudflare, Vercel, Railway, AWS…) are not
 * matched at all: their CVEs concern products the site owner does not run
 * (a VPN client, a CLI), and the platform patches its own infrastructure.
 */

import { logger } from "./logger";
import { type CpeRange, type NvdCve } from "./cveMonitorMatch";
export { TECH_CPE, bareTechName, detectedVersion, compareVersions, versionInRange, matchCvesToTechnologies, describeAffected } from "./cveMonitorMatch";
export type { CpeRange, NvdCve, MatchBasis, CveMatch } from "./cveMonitorMatch";

// ─── NVD ─────────────────────────────────────────────────────────────────────

interface NvdCpeMatch {
  vulnerable: boolean;
  criteria: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

interface NvdRawCve {
  id: string;
  vulnStatus?: string;
  published: string;
  descriptions: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
    cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
    cvssMetricV2?: Array<{ cvssData: { baseScore: number }; baseSeverity: string }>;
  };
  configurations?: Array<{ nodes: Array<{ cpeMatch?: NvdCpeMatch[] }> }>;
}

interface NvdApiResponse {
  vulnerabilities?: Array<{ cve: NvdRawCve }>;
  totalResults?: number;
  resultsPerPage?: number;
  startIndex?: number;
}

/** Turn one raw NVD record into the shape the matcher uses. Exported for tests. */
export function parseNvdCve(cve: NvdRawCve): NvdCve {
  const desc = cve.descriptions.find((d) => d.lang === "en")?.value ?? "";
  const v31 = cve.metrics?.cvssMetricV31?.[0];
  const v30 = cve.metrics?.cvssMetricV30?.[0];
  const v2 = cve.metrics?.cvssMetricV2?.[0];
  const score = v31?.cvssData.baseScore ?? v30?.cvssData.baseScore ?? v2?.cvssData.baseScore ?? null;
  const severity = (v31?.cvssData.baseSeverity ?? v30?.cvssData.baseSeverity ?? v2?.baseSeverity ?? "UNKNOWN").toUpperCase();

  const products: CpeRange[] = [];
  for (const cfg of cve.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        // vulnerable:false entries are the platform a flaw needs ("runs on
        // Windows"), not the product that has it.
        if (!m.vulnerable) continue;
        const parts = m.criteria.split(":");
        // cpe:2.3:<part>:<vendor>:<product>:<version>:…  Applications only.
        if (parts.length < 6 || parts[2] !== "a") continue;
        const v = parts[5]!;
        products.push({
          product: `${parts[3]}:${parts[4]}`,
          exactVersion: v === "*" || v === "-" ? null : v,
          ...(m.versionStartIncluding ? { startIncluding: m.versionStartIncluding } : {}),
          ...(m.versionStartExcluding ? { startExcluding: m.versionStartExcluding } : {}),
          ...(m.versionEndIncluding ? { endIncluding: m.versionEndIncluding } : {}),
          ...(m.versionEndExcluding ? { endExcluding: m.versionEndExcluding } : {}),
        });
      }
    }
  }

  return {
    id: cve.id,
    description: desc,
    severity,
    cvssScore: score,
    publishedDate: cve.published,
    status: cve.vulnStatus ?? "",
    products,
  };
}

export interface FetchResult {
  cves: NvdCve[];
  /** False when NVD could not be read, so a quiet run is not mistaken for "nothing new". */
  ok: boolean;
}

const PAGE_SIZE = 2000;
/** A cap so a mis-set window cannot page forever. 10 pages = 20,000 CVEs. */
const MAX_PAGES = 10;

/**
 * Every CVE NVD created or changed within the window, all pages.
 *
 * By LAST-MODIFIED date, not published date: a new CVE usually arrives with no
 * product data and gains it when NVD analyses it days later. Querying by
 * publication date checked each CVE once, before it could match anything.
 */
export async function fetchChangedCves(startDate: Date, endDate: Date): Promise<FetchResult> {
  const fmt = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, ".000");
  const apiKey = process.env["NVD_API_KEY"];
  const pause = apiKey ? 700 : 6500;
  const cves: NvdCve[] = [];

  for (let page = 0, startIndex = 0; page < MAX_PAGES; page++) {
    const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    url.searchParams.set("lastModStartDate", fmt(startDate));
    url.searchParams.set("lastModEndDate", fmt(endDate));
    url.searchParams.set("resultsPerPage", String(PAGE_SIZE));
    url.searchParams.set("startIndex", String(startIndex));

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 60_000);
    try {
      const res = await fetch(url.toString(), {
        signal: ctrl.signal,
        headers: { Accept: "application/json", ...(apiKey ? { apiKey } : {}) },
      });
      if (!res.ok) {
        logger.error({ status: res.status, page }, "NVD API returned a non-200 response; CVE check incomplete");
        return { cves, ok: false };
      }
      const data = (await res.json()) as NvdApiResponse;
      const raw = data.vulnerabilities ?? [];
      for (const entry of raw) cves.push(parseNvdCve(entry.cve));

      const total = data.totalResults ?? raw.length;
      startIndex += raw.length;
      if (raw.length === 0 || startIndex >= total) return { cves, ok: true };
    } catch (err) {
      logger.error({ err, page }, "NVD API fetch failed; CVE check incomplete");
      return { cves, ok: false };
    } finally {
      clearTimeout(timer);
    }
    await new Promise((r) => setTimeout(r, pause));
  }

  logger.error({ pages: MAX_PAGES }, "NVD window exceeded the page cap; CVE check incomplete");
  return { cves, ok: false };
}
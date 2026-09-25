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

/** One vulnerable-product entry from a CVE's configurations. */
export interface CpeRange {
  /** "vendor:product", e.g. "f5:nginx". */
  product: string;
  /** Exact version from the CPE, when the entry names one ("1.18.0"); null for "*" or "-". */
  exactVersion: string | null;
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
}

export interface NvdCve {
  id: string;
  description: string;
  severity: string;
  cvssScore: number | null;
  publishedDate: string;
  /** NVD's workflow status: Analyzed, Modified, Awaiting Analysis, Rejected… */
  status: string;
  /** Vulnerable products only; empty until NVD has analysed the CVE. */
  products: CpeRange[];
}

/**
 * Technology name as the fingerprinter emits it (techFingerprint.ts / scanner.ts)
 * → the NVD vendor:product pairs for that software. Every pair was checked
 * against NVD's CPE dictionary on 2026-09-24. Software sometimes appears under
 * more than one vendor after a transfer (nginx: nginx:nginx, then f5:nginx).
 */
export const TECH_CPE: Record<string, string[]> = {
  // Web servers and proxies
  "Nginx":          ["f5:nginx", "nginx:nginx"],
  "Apache":         ["apache:http_server"],
  "OpenResty":      ["openresty:openresty"],
  "IIS":            ["microsoft:internet_information_services"],
  "LiteSpeed":      ["litespeedtech:litespeed_web_server", "litespeedtech:openlitespeed"],
  "Caddy":          ["caddyserver:caddy"],
  "Varnish Cache":  ["varnish-cache:varnish_cache"],
  "Squid Proxy":    ["squid-cache:squid"],
  "Envoy Proxy":    ["envoyproxy:envoy"],
  "Gunicorn":       ["gunicorn:gunicorn"],
  "Tomcat":         ["apache:tomcat"],
  "OpenSSL":        ["openssl:openssl"],
  // Languages and runtimes
  "PHP":            ["php:php"],
  "Python":         ["python:python"],
  "Node.js":        ["nodejs:node.js"],
  "Kestrel (.NET)": ["microsoft:asp.net_core"],
  "ASP.NET":        ["microsoft:asp.net_core", "microsoft:asp.net"],
  // Frameworks
  "Django":         ["djangoproject:django"],
  "Ruby on Rails":  ["rubyonrails:rails", "rubyonrails:ruby_on_rails"],
  "Laravel":        ["laravel:framework", "laravel:laravel"],
  "Express.js":     ["expressjs:express", "openjsf:express"],
  "Spring":         ["vmware:spring_framework", "pivotal_software:spring_framework"],
  "Next.js":        ["vercel:next.js", "zeit:next.js"],
  "Nuxt.js":        ["nuxt:nuxt", "nuxtjs:nuxt.js"],
  "Gatsby":         ["gatsbyjs:gatsby"],
  // Front-end libraries (only matched when the scan read a version)
  "Angular":        ["angular:angular", "angularjs:angular.js"],
  "React":          ["facebook:react"],
  "Ember.js":       ["emberjs:ember.js"],
  "jQuery":         ["jquery:jquery"],
  "Lodash":         ["lodash:lodash"],
  "Bootstrap":      ["getbootstrap:bootstrap"],
  // CMS and commerce
  "WordPress":      ["wordpress:wordpress"],
  "Drupal":         ["drupal:drupal"],
  // NVD writes the "!" in Joomla's product name escaped, as it appears here.
  "Joomla":         ["joomla:joomla\\!"],
  "Ghost":          ["ghost:ghost"],
  "Magento":        ["magento:magento", "adobe:magento", "adobe:commerce"],
  "WooCommerce":    ["woocommerce:woocommerce", "automattic:woocommerce"],
  // Not listed, because NVD has no product entry to match against (checked):
  // Vue.js, Svelte, Remix, htmx, Alpine.js, Backbone.js. Hosting and SaaS
  // platforms are left out on purpose; see the file header.
};

/** What a match is based on, carried into the alert so it is never overstated. */
export type MatchBasis = "affected" | "unconfirmed";

export interface CveMatch {
  cve: NvdCve;
  /** The technology as detected, version included ("Nginx 1.18.0"). */
  matchedTech: string;
  basis: MatchBasis;
}

// ─── Versions ────────────────────────────────────────────────────────────────

/**
 * The bare technology name, with any trailing version removed.
 *
 * scanner.ts appends versions for display ("Nginx" → "Nginx 1.18.0") while the
 * table is keyed on the bare name. Only a trailing version-shaped token is
 * stripped: splitting on the first space would break "Ruby on Rails".
 */
export function bareTechName(tech: string): string {
  return tech.replace(/\s+v?\d[\w.-]*$/i, "").trim();
}

/** The version the scanner detected, if the name carries one ("Nginx 1.18.0" → "1.18.0"). */
export function detectedVersion(tech: string): string | null {
  const m = /\s+v?(\d[\w.-]*)$/i.exec(tech.trim());
  return m ? m[1]! : null;
}

/**
 * Compare two dotted versions numerically: 1.9 < 1.10, 1.19.3.2 > 1.19.3.
 * A trailing distro or build suffix ("1.18.0-1ubuntu", "8.1.2p1") is ignored,
 * because the upstream number is what NVD's ranges are written in.
 * Returns negative, zero or positive, like a sort comparator.
 */
export function compareVersions(a: string, b: string): number {
  const nums = (v: string) =>
    v
      .replace(/^v/i, "")
      .split(/[-+~_ ]/)[0]!
      .split(".")
      .map((part) => {
        const n = /^\d+/.exec(part);
        return n ? parseInt(n[0], 10) : 0;
      });
  const x = nums(a);
  const y = nums(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** Whether a detected version falls inside one vulnerable-product entry. */
export function versionInRange(version: string, r: CpeRange): boolean {
  if (r.exactVersion) return compareVersions(version, r.exactVersion) === 0;
  const hasRange = r.startIncluding || r.startExcluding || r.endIncluding || r.endExcluding;
  // "*" with no range means every version, which NVD uses for products whose
  // affected versions it could not bound. Treated as affected.
  if (!hasRange) return true;
  if (r.startIncluding && compareVersions(version, r.startIncluding) < 0) return false;
  if (r.startExcluding && compareVersions(version, r.startExcluding) <= 0) return false;
  if (r.endIncluding && compareVersions(version, r.endIncluding) > 0) return false;
  if (r.endExcluding && compareVersions(version, r.endExcluding) >= 0) return false;
  return true;
}

// ─── Matching ────────────────────────────────────────────────────────────────

const SERIOUS = new Set(["CRITICAL", "HIGH"]);

/**
 * The CVEs that affect the detected software, each with the basis for saying so.
 *
 * No description matching of any kind: a CVE matches only when its structured
 * product data names the software. See the file header for the rules.
 */
export function matchCvesToTechnologies(technologies: string[], cves: NvdCve[]): CveMatch[] {
  const results: CveMatch[] = [];

  for (const tech of technologies) {
    const products = TECH_CPE[bareTechName(tech)];
    if (!products || products.length === 0) continue;
    const version = detectedVersion(tech);

    for (const cve of cves) {
      if (cve.status.toLowerCase() === "rejected") continue;
      const entries = cve.products.filter((p) => products.includes(p.product));
      if (entries.length === 0) continue;

      let basis: MatchBasis | null;
      if (version) {
        basis = entries.some((e) => versionInRange(version, e)) ? "affected" : null;
      } else {
        // Without a version this is "the product has a new vulnerability", which is
        // only worth an interruption when it is serious.
        basis = SERIOUS.has(cve.severity.toUpperCase()) ? "unconfirmed" : null;
      }
      if (!basis) continue;

      if (!results.some((r) => r.cve.id === cve.id && r.matchedTech === tech)) {
        results.push({ cve, matchedTech: tech, basis });
      }
    }
  }

  return results;
}

/**
 * How a match is described wherever a person reads it (the alert row, the email,
 * the webhook). The two bases must never read the same.
 */
export function describeAffected(match: Pick<CveMatch, "matchedTech" | "basis">): string {
  return match.basis === "affected"
    ? `${match.matchedTech} (detected version is in the affected range)`
    : `${bareTechName(match.matchedTech)} (version not detected; check whether yours is affected)`;
}

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

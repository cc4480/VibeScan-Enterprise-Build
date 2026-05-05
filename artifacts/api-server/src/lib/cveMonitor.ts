/**
 * CVE Monitor — polls the NVD (National Vulnerability Database) API for
 * newly published CVEs and matches them against the technology stack
 * detected in the most recent scan report for each monitored subscription.
 *
 * NVD API v2: https://services.nvd.nist.gov/rest/json/cves/2.0
 * Rate limit: 1 request per 6 seconds without an API key.
 */

import { logger } from "./logger";

export interface NvdCve {
  id: string;
  description: string;
  severity: string;
  cvssScore: number | null;
  publishedDate: string;
}

/**
 * Map of technology names (as detected by the scanner) to search keywords
 * for matching against NVD CVE descriptions.
 */
const TECH_KEYWORDS: Record<string, string[]> = {
  "WordPress":            ["wordpress"],
  "Apache":               ["apache http", "apache httpd"],
  "Nginx":                ["nginx"],
  "Node.js":              ["node.js", "nodejs"],
  "React":                ["facebook react", "reactjs"],
  "PHP":                  ["php"],
  "jQuery":               ["jquery"],
  "Django":               ["django"],
  "Ruby on Rails":        ["ruby on rails"],
  "Laravel":              ["laravel"],
  "Express":              ["expressjs", "express.js"],
  "Vue.js":               ["vue.js", "vuejs"],
  "Angular":              ["angular"],
  "Next.js":              ["next.js", "vercel next"],
  "Drupal":               ["drupal"],
  "Joomla":               ["joomla"],
  "Tomcat":               ["apache tomcat"],
  "Spring":               ["spring framework", "springframework"],
  "IIS":                  ["microsoft iis", "internet information services"],
  "OpenSSL":              ["openssl"],
  "Cloudflare":           ["cloudflare"],
  "Vercel":               ["vercel"],
  "Netlify":              ["netlify"],
  "AWS":                  ["amazon aws", "amazon web services"],
  "AWS CloudFront":       ["amazon cloudfront"],
  "Azure":                ["microsoft azure"],
  "Google Cloud / GFE":   ["google cloud"],
  "Fly.io":               ["fly.io"],
  "Railway":              ["railway"],
  "Render":               ["render.com"],
  "Ghost":                ["ghost cms", "ghost blog"],
  "Squarespace":          ["squarespace"],
  "Webflow":              ["webflow"],
  "Shopify":              ["shopify"],
  "WooCommerce":          ["woocommerce"],
  "Magento":              ["magento"],
  "Kestrel (.NET)":       ["kestrel", ".net core", "asp.net"],
  "Gunicorn":             ["gunicorn"],
  "LiteSpeed":            ["litespeed"],
  "OpenResty":            ["openresty"],
};

interface NvdApiResponse {
  vulnerabilities?: Array<{
    cve: {
      id: string;
      descriptions: Array<{ lang: string; value: string }>;
      published: string;
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: { baseScore: number; baseSeverity: string };
        }>;
        cvssMetricV30?: Array<{
          cvssData: { baseScore: number; baseSeverity: string };
        }>;
        cvssMetricV2?: Array<{
          cvssData: { baseScore: number };
          baseSeverity: string;
        }>;
      };
    };
  }>;
  totalResults?: number;
}

/**
 * Fetches CVEs published within the specified time window from NVD API v2.
 * Returns up to 2000 results per call (NVD maximum).
 */
export async function fetchRecentCves(startDate: Date, endDate: Date): Promise<NvdCve[]> {
  const fmt = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, ".000");

  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("pubStartDate", fmt(startDate));
  url.searchParams.set("pubEndDate", fmt(endDate));
  url.searchParams.set("resultsPerPage", "2000");

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 30_000);

  try {
    const res = await fetch(url.toString(), {
      signal: ctrl.signal,
      headers: { Accept: "application/json" },
    });
    clearTimeout(timer);

    if (!res.ok) {
      logger.warn({ status: res.status }, "NVD API returned non-200 response");
      return [];
    }

    const data = (await res.json()) as NvdApiResponse;
    const raw = data.vulnerabilities ?? [];

    return raw.map((entry) => {
      const cve = entry.cve;
      const desc = cve.descriptions.find((d) => d.lang === "en")?.value ?? "";

      const v31 = cve.metrics?.cvssMetricV31?.[0];
      const v30 = cve.metrics?.cvssMetricV30?.[0];
      const v2  = cve.metrics?.cvssMetricV2?.[0];

      const score = v31?.cvssData.baseScore ?? v30?.cvssData.baseScore ?? v2?.cvssData.baseScore ?? null;
      const severity = (
        v31?.cvssData.baseSeverity ??
        v30?.cvssData.baseSeverity ??
        v2?.baseSeverity ??
        "UNKNOWN"
      ).toUpperCase();

      return {
        id: cve.id,
        description: desc,
        severity,
        cvssScore: score,
        publishedDate: cve.published,
      };
    });
  } catch (err) {
    clearTimeout(timer);
    logger.warn({ err }, "NVD API fetch failed");
    return [];
  }
}

/**
 * Given a list of detected technologies and a list of recent CVEs,
 * returns the CVEs that are relevant to those technologies.
 */
export function matchCvesToTechnologies(
  technologies: string[],
  cves: NvdCve[],
): Array<{ cve: NvdCve; matchedTech: string }> {
  const results: Array<{ cve: NvdCve; matchedTech: string }> = [];

  for (const tech of technologies) {
    const keywords = TECH_KEYWORDS[tech];
    if (!keywords || keywords.length === 0) continue;

    for (const cve of cves) {
      const descLower = cve.description.toLowerCase();
      const matched = keywords.some((kw) => descLower.includes(kw));
      if (matched) {
        if (!results.some((r) => r.cve.id === cve.id && r.matchedTech === tech)) {
          results.push({ cve, matchedTech: tech });
        }
      }
    }
  }

  return results;
}

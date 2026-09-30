/**
 * Site crawler — follows same-domain links, then for each inner page:
 *   1. Checks security response headers (reports gaps vs. root page)
 *   2. Probes for sensitive files relative to the discovered path
 *   3. Checks cookie security flags on Set-Cookie headers
 *
 * The root URL is often served via a CDN that injects security headers, while
 * inner routes (especially /api/* paths) bypass the CDN and hit the origin
 * server directly — missing headers entirely. This catches those gaps.
 *
 * Findings include the specific affected paths in their evidence.
 */

import { detectChallengePage } from "./challengePage.js";
import type { ScanVulnerability } from "./scanner";
import { PATH_PROBES } from "./crawler-data";
import { isDestructiveUrl } from "./destructive";
import { PAGE_TIMEOUT_MS, CRAWL_TIMEOUT_MS, extractInternalLinks, fetchPage } from "./crawlerFetch";
import { HIGH_VALUE_PROBE_PATHS, probePathSensitiveFiles } from "./crawlerProbes";
import { confirmHeaderGaps, snapshotHeaders, buildHeaderGapVulns } from "./crawlerHeaders";
import { checkPageCookies, seedCookieIssuesFromRoot } from "./crawlerCookies";
export { extractInternalLinks } from "./crawlerFetch";
export { HIGH_VALUE_PROBE_PATHS } from "./crawlerProbes";
export { confirmHeaderGaps, buildHeaderGapVulns } from "./crawlerHeaders";
export { redactCookieValue, seedCookieIssuesFromRoot } from "./crawlerCookies";

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export interface CrawlResult {
  vulnerabilities: ScanVulnerability[];
  /** URLs that were actually fetched (status < 400, not redirected off-domain) */
  pagesVisited: string[];
  /**
   * High-value probe paths (from HIGH_VALUE_PROBE_PATHS) that returned HTTP 404.
   * Only explicit probes are included — crawled links that 404'd are excluded.
   * Paths that failed with other status codes (401, 403, 5xx), timed out, or
   * were redirected off-domain are also excluded; they are not "not found", they
   * were actively blocked or unavailable.
   */
  probedNotFound: string[];
}

export async function crawlAndCheck(
  rootUrl: string,
  rootHtml: string,
  rootHeaders: Record<string, string>,
  // The root response's cookies, already split by getSetCookie(). Passed in
  // rather than re-derived from rootHeaders: splitting a joined Set-Cookie on
  // commas shears cookies at the comma inside expires=, which seeds the wrong
  // names and defeats the deduplication entirely.
  rootSetCookies: string[],
  maxPages: number,
): Promise<CrawlResult> {
  let origin: string;
  let expectedHostname: string;
  try {
    const parsed = new URL(rootUrl);
    origin = parsed.origin;
    expectedHostname = parsed.hostname;
  } catch {
    return { vulnerabilities: [], pagesVisited: [], probedNotFound: [] };
  }

  // ── URL list construction ────────────────────────────────────────────────
  //
  // Two separate sources:
  //   1. linkedUrls  — URLs discovered in the root page HTML (capped by maxPages)
  //   2. probedUrls  — HIGH_VALUE_PROBE_PATHS always checked regardless of maxPages
  //
  // Probed paths skip any path that overlaps with a crawled link (same pathname)
  // and any path that matches the dangerous-action pattern.

  const linkedUrls: string[] = maxPages > 0
    ? extractInternalLinks(rootHtml, rootUrl).slice(0, maxPages)
    : [];

  const linkedPathnames = new Set(
    linkedUrls.map((u) => { try { return new URL(u).pathname; } catch { return u; } }),
  );

  const probedUrls: string[] = HIGH_VALUE_PROBE_PATHS
    .map((p) => `${origin}${p}`)
    .filter((u) => !isDestructiveUrl(u))
    .filter((u) => { try { return !linkedPathnames.has(new URL(u).pathname); } catch { return false; } });

  // Set of probed URLs for labelling findings — checked with full URL equality
  const probedSet = new Set<string>(probedUrls);

  // If there's nothing to check at all, bail early
  if (linkedUrls.length === 0 && probedUrls.length === 0) {
    return { vulnerabilities: [], pagesVisited: [], probedNotFound: [] };
  }

  // The root's headers are a baseline for "what this site sends" only when the root IS the site.
  // When an edge answered with its own interstitial (Reddit's proof-of-work page carries a CSP of
  // its own, verified 2026-09-29) those headers describe the edge, and every inner route that
  // lacks them would be reported as a regression from a policy the site never set. No baseline,
  // no comparison: with nothing recorded as present at the root, no gap can be raised.
  const rootIsChallenge = detectChallengePage(200, rootHtml, rootHeaders).isChallenge;
  const rootSnapshot = rootIsChallenge
    ? { hsts: false, csp: false, xfo: false, xcto: false, rp: false }
    : snapshotHeaders(rootHeaders);
  const isHttps = rootUrl.startsWith("https://");

  // Shared dedup set for cookie findings — prevents the same cookie issue
  // (e.g. GAESA missing Secure) from being filed once per crawled page.
  // Key format: "issueType::cookieName"
  const seenCookieIssues = seedCookieIssuesFromRoot(rootSetCookies);

  // Track which header is missing on which paths (for gap aggregation)
  const gapMap = new Map<keyof typeof rootSnapshot, string[]>([
    ["hsts", []],
    ["csp",  []],
    ["xfo",  []],
    ["xcto", []],
    ["rp",   []],
  ]);

  const crawlDeadline = Date.now() + CRAWL_TIMEOUT_MS;
  const perPageFindings: ScanVulnerability[] = [];
  const pagesVisited: string[] = [];
  const probedDirs = new Set<string>();

  // Minimum remaining budget required to start a new page fetch (avoids starting
  // a request that can never complete within the overall time bound)
  const MIN_BUDGET_MS = 1_000;

  /**
   * Fetch and analyse a single page.
   * @param url          Full URL to fetch
   * @param discoveredBy Whether this URL came from HTML crawling or direct probing
   * @returns The HTTP status code returned by the server, or null if the request
   *          was not attempted (budget exhausted) or resulted in a network error.
   *          Callers can check for 404 specifically to record "probed but not found".
   */
  const processPage = async (url: string, discoveredBy: "crawl" | "probe"): Promise<number | null> => {
    const remaining = crawlDeadline - Date.now();
    if (remaining < MIN_BUDGET_MS) return null;

    // Cap per-fetch timeout to whatever budget remains (hard deadline enforcement)
    const fetchTimeout = Math.min(PAGE_TIMEOUT_MS, remaining);

    const page = await fetchPage(url, fetchTimeout);
    if (!page || page.status === 0 || page.status >= 400) return page?.status ?? null;

    // Verify we didn't get redirected off-domain (catch-all login redirects, etc.)
    try {
      const finalHostname = new URL(page.finalUrl).hostname;
      if (finalHostname !== expectedHostname) return page.status;
    } catch {
      return page.status;
    }

    // Only documents are routes. The href regex above matches every href in the
    // markup, including <link rel="preload"> and <link rel="stylesheet">, so
    // bundles and images arrive here looking like pages. Judging them for
    // missing X-Frame-Options is meaningless — a stylesheet cannot be framed —
    // and it inflated the count: scanning google.com reported three routes
    // missing the header when only two were pages, the third being a preloaded
    // JS bundle.
    const contentType = (
      Object.entries(page.headers).find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? ""
    ).toLowerCase();
    if (contentType && !/text\/html|application\/xhtml/.test(contentType)) {
      return page.status;
    }

    // An inner route the edge answered with its own challenge or block page is not a page of
    // the application: its headers and cookies are the edge's, so it can be neither a header gap
    // nor a cookie finding for the site. It is also not "visited" for the checks that follow.
    if (detectChallengePage(page.status, page.body, page.headers).isChallenge) {
      return page.status;
    }

    // Record this URL as successfully visited
    pagesVisited.push(url);

    // ── Header gap tracking ────────────────────────────────────────────────
    const snap = snapshotHeaders(page.headers);
    for (const key of Object.keys(rootSnapshot) as (keyof typeof rootSnapshot)[]) {
      if (rootSnapshot[key] && !snap[key]) {
        const list = gapMap.get(key) ?? [];
        list.push(url);
        gapMap.set(key, list);
      }
    }

    // ── Cookie checks ──────────────────────────────────────────────────────
    perPageFindings.push(
      ...checkPageCookies(page.setCookies, url, isHttps, seenCookieIssues, discoveredBy),
    );

    // ── Sensitive file probes under this path's directory ──────────────────
    const probeRemaining = crawlDeadline - Date.now();
    if (probeRemaining >= MIN_BUDGET_MS) {
      const probeTimeout = Math.min(PAGE_TIMEOUT_MS, probeRemaining);
      const pathFindings = await probePathSensitiveFiles(url, origin, expectedHostname, probeTimeout, probedDirs);
      perPageFindings.push(...pathFindings);
    }

    return page.status;
  };

  // Process linked pages first (sequential — respects time budget per iteration)
  for (const url of linkedUrls) {
    if (Date.now() + MIN_BUDGET_MS > crawlDeadline) break;
    await processPage(url, "crawl");
  }

  // Process directly-probed high-value paths (also sequential to respect budget).
  // Collect those that returned exactly HTTP 404 — "probed but not found" in the report.
  const probedNotFound: string[] = [];
  for (const url of probedUrls) {
    if (Date.now() + MIN_BUDGET_MS > crawlDeadline) break;
    const status = await processPage(url, "probe");
    if (status === 404) probedNotFound.push(url);
  }

  await confirmHeaderGaps(gapMap, async (url) => {
    const remaining = crawlDeadline - Date.now();
    if (remaining < MIN_BUDGET_MS) return null;
    return fetchPage(url, Math.min(PAGE_TIMEOUT_MS, remaining));
  });

  // Aggregate header gap findings (one finding per header type covering all affected paths)
  const headerGapFindings = buildHeaderGapVulns(rootSnapshot, gapMap, probedSet);

  // Deduplicate: the same file type found under several directories is one
  // finding (same host, same evidence class); the extra locations are listed in
  // its evidence rather than filed again. Other findings dedupe on name + evidence.
  const pathProbeNames = new Set(PATH_PROBES.map((p) => p.name));
  const seenSensitiveKeys = new Set<string>();
  const firstByProbe = new Map<string, ScanVulnerability>();
  const extraLocations = new Map<string, string[]>();
  const dedupedPerPage: ScanVulnerability[] = [];
  for (const finding of perPageFindings) {
    if (pathProbeNames.has(finding.name)) {
      const first = firstByProbe.get(finding.name);
      if (first) {
        const loc = /^GET (\S+)/.exec(finding.evidence ?? "")?.[1];
        if (loc) extraLocations.set(finding.name, [...(extraLocations.get(finding.name) ?? []), loc]);
        continue;
      }
      firstByProbe.set(finding.name, finding);
      dedupedPerPage.push(finding);
      continue;
    }
    const key = `${finding.name}::${finding.evidence?.slice(0, 80) ?? ""}`;
    if (!seenSensitiveKeys.has(key)) {
      seenSensitiveKeys.add(key);
      dedupedPerPage.push(finding);
    }
  }
  for (const [name, locs] of extraLocations) {
    const first = firstByProbe.get(name)!;
    const shown = locs.slice(0, 5).join(", ");
    first.evidence += `\nAlso found at: ${shown}${locs.length > 5 ? ` (+${locs.length - 5} more)` : ""}`;
  }

  return {
    vulnerabilities: [...headerGapFindings, ...dedupedPerPage],
    pagesVisited,
    probedNotFound,
  };
}
/**
 * Every check a scan can run, itemised, and the test that runs each one.
 *
 * "129 checks" was a number derived from reading the code and typed into a data
 * file, then listed in a different shape from the scan's own 39-line test log.
 * A reader comparing the two saw 129 against 39. They are different things: a
 * TEST is a unit the scanner runs and records (the ledger, testLedger.ts); a CHECK
 * is one piece of detection logic inside a test that can produce a finding. This
 * catalog is the bridge, so a scan can show both and they add up.
 *
 * Counting method (unchanged): a check is one finding site with its own name.
 * The same logic applied to more inputs is not more checks, so a table of 78
 * sensitive paths is one check. Status notices that are not vulnerabilities
 * ("Scan session expired", "Active testing was skipped") are not checks.
 *
 * Nothing here is trusted on its own: checkCatalog.test.ts requires every entry's
 * `needle` to appear in the source file that raises it, so a check that is renamed
 * or removed without updating this file fails the build. The total is derived from
 * the entries below, never typed.
 */
import type { CatalogTest } from "./checkCatalogTypes";
import { CATALOG_HTTP } from "./checkCatalogHttp";
import { CATALOG_SURFACE } from "./checkCatalogSurface";
import { CATALOG_REPO } from "./checkCatalogRepo";

export * from "./checkCatalogTypes";

/** What a website scan runs. A repository-only scan runs CATALOG_REPO instead (lib/repoOnlyScan.ts). */
export const WEBSITE_CATALOG: CatalogTest[] = [...CATALOG_HTTP, ...CATALOG_SURFACE];

export const CATALOG: CatalogTest[] = [...WEBSITE_CATALOG, ...CATALOG_REPO];

const countChecks = (tests: CatalogTest[]) => tests.reduce((n, t) => n + t.checks.length, 0);

/** The number of checks a website scan carries, and a repository scan. Derived, so they cannot drift from the lists. */
export const WEBSITE_TOTAL_CHECKS = countChecks(WEBSITE_CATALOG);
export const REPO_TOTAL_CHECKS = countChecks(CATALOG_REPO);
/** Every check the catalog lists, website and repository together. */
export const TOTAL_CHECKS = countChecks(CATALOG);

/** A ledger record's checks, or none when the test is a step with no findings of its own (DNS lookups). */
export function catalogFor(recordName: string): CatalogTest | null {
  let best: CatalogTest | null = null;
  for (const t of CATALOG) {
    if (recordName === t.test || recordName.startsWith(`${t.test} (`) || recordName.startsWith(`${t.test} `)) {
      // The longest key wins, so "site crawl" never captures a more specific test.
      if (!best || t.test.length > best.test.length) best = t;
    }
  }
  return best;
}

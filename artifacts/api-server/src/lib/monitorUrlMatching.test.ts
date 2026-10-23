import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The monitor looks a site's scans up by URL, and a saved report is stored under the URL the scan ENDED on
 * (`https://seclayer.app/`) while a subscription keeps the address as typed (`https://seclayer.app`). An exact `eq()` on those
 * columns never matched, so a scanned site looked unscanned, its history was empty and the CVE watch skipped it. Every one of
 * these lookups goes through sameSite() (urlKey.ts). This holds them to it, so a new lookup written with eq() is caught.
 */
const FILES = [
  "routes/monitorShared.ts", "routes/monitorCreate.ts", "routes/monitorHistory.ts", "routes/monitorList.ts",
  "lib/monitorSchedulerCve.ts", "lib/monitorSchedulerCert.ts",
];
const root = join(__dirname, "..");

describe("monitor URL lookups match by site, not by exact string", () => {
  for (const f of FILES) {
    it(`${f} compares target URLs with sameSite()`, () => {
      const src = readFileSync(join(root, f), "utf8");
      expect(src).toContain("sameSite(");
      expect(src, "an exact eq() on a target URL column came back").not.toMatch(/eq\(\s*(?:reportsTable|scansTable|monitorSubscriptionsTable)\.targetUrl/);
    });
  }
});

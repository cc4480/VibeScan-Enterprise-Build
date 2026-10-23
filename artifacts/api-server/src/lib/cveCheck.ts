/**
 * CVE / known-vulnerability checker.
 *
 * Extracts software version numbers from page HTML and HTTP headers,
 * then cross-references them against the OSV.dev vulnerability database
 * (https://osv.dev — free, no API key required).
 *
 * Covers: jQuery, Bootstrap, Lodash, Moment.js, Vue.js, Angular,
 * React (CDN-hosted), WordPress, Drupal, Joomla, plus PHP, Nginx,
 * Apache, IIS, OpenResty end-of-life / CVE detection from headers.
 *
 * Results are cached in-process per (package, version, ecosystem) to
 * avoid duplicate OSV.dev API calls within the same server lifetime.
 */

import type { ScanVulnerability } from "./scanner";
import { queryOsv, extractCvss, cvssToSeverity, extractFixedVersion, cveIds } from "./cveCheckOsv";
import { extractVersionedTechnologies } from "./cveCheckVersions";
import { checkLocalVulns } from "./cveCheckLocal";
import { vuln } from "./cveCheckCore";
export { OSV_CACHE_MAX_SIZE, queryOsv, extractCvss, cvssToSeverity, extractFixedVersion, cveIds } from "./cveCheckOsv";
export { extractVersionedTechnologies } from "./cveCheckVersions";
export { warnIfLocalDataStale } from "./cveCheckLocal";
export type { OsvVuln } from "./cveCheckOsv";

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function checkForKnownVulnerabilities(
  html: string,
  headers: Record<string, string>,
  /** The moment end-of-life dates are judged against. The real clock unless a caller needs another date. */
  opts: { now?: Date } = {},
): Promise<ScanVulnerability[]> {
  const detected = extractVersionedTechnologies(html, headers);
  if (detected.length === 0) return [];

  const findings: ScanVulnerability[] = [];

  // 1. Local checks (instant, no network)
  findings.push(...checkLocalVulns(detected, opts.now));

  // 2. OSV.dev queries for npm + CMS packages (parallel, cached per version)
  const osvTargets = detected.filter((d) => d.ecosystem !== "local");

  const osvResults = await Promise.allSettled(
    osvTargets.map((d) => queryOsv(d.packageName, d.version, d.ecosystem)),
  );

  for (let i = 0; i < osvTargets.length; i++) {
    const target = osvTargets[i];
    const result = osvResults[i];
    if (result?.status !== "fulfilled") continue;

    const vulns = result.value;
    if (vulns.length === 0) continue;

    // Sort by CVSS score descending, take worst 2
    const sorted = vulns
      .map((v) => ({ v, score: extractCvss(v) ?? 0 }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 2);

    for (const { v: osvVuln, score } of sorted) {
      const cves = cveIds(osvVuln);
      const fixedVersion = extractFixedVersion(osvVuln);
      const cveList = cves.length > 0 ? cves.join(", ") : osvVuln.id;

      findings.push(vuln({
        name: `${target.displayName} ${target.version} — Known Vulnerability (${cveList})`,
        severity: cvssToSeverity(score),
        category: "Outdated Software / Known CVE",
        description:
          `${target.displayName} version ${target.version} has a known vulnerability: ` +
          `${osvVuln.summary ?? "See CVE details."}` +
          (score > 0 ? ` CVSS score: ${score}.` : ""),
        evidence:
          `Detected: ${target.displayName} ${target.version}\n` +
          `CVE(s): ${cveList}\n` +
          (fixedVersion ? `Fixed in: ${fixedVersion}\n` : "") +
          (osvVuln.details ? `Details: ${osvVuln.details.slice(0, 300)}` : ""),
        solution:
          fixedVersion
            ? `Upgrade ${target.displayName} to version ${fixedVersion} or later. ` +
              `Update CDN reference URLs or your package.json dependency.`
            : `Upgrade ${target.displayName} to the latest stable version. ` +
              `Check ${target.ecosystem === "npm" ? "https://www.npmjs.com/package/" + target.packageName : "the vendor advisory"} for patched releases.`,
        cweId: "CWE-1104",
        cvssScore: score > 0 ? score : null,
        wstgId: "WSTG-INFO-09",
      }));
    }
  }

  return findings;
}
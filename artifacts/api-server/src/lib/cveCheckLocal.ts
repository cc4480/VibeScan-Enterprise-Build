/** The bundled end-of-life / known-vulnerable data check, and its staleness warning. */
import type { ScanVulnerability } from "./scanner";
import { logger } from "./logger";
import { getLivePhpEol, getLiveNginxEolCycles, getLiveApacheEolCycles, getEolDataFetchedAt } from "./eolFetcher";
import { classifyEol, matchRange, rangeFinding } from "./bannerRules";
import { type DetectedVersion, NGINX_VULN_RANGES, APACHE_VULN_RANGES, IIS_EOL_MAJOR } from "./cve-patterns";
import { vuln } from "./cveCheckCore";
import { cvssToSeverity } from "./cveCheckOsv";

// ─────────────────────────────────────────────────────────────────────────────
// LOCAL CHECKS (no network call)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// LOCAL DATA FRESHNESS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ISO date when the local vuln tables below (PHP_EOL, NGINX_VULN_RANGES,
 * APACHE_VULN_RANGES, IIS_EOL_MAJOR) were last reviewed and updated.
 * Update this whenever you add, modify, or verify the data below.
 */
export const LOCAL_VULN_DATA_UPDATED = "2026-09-21";

export const LOCAL_DATA_STALE_DAYS = 90;

/**
 * Logs a warning at startup for whichever local data set has gone stale.
 * Call this once from startWorker().
 *
 * Two independent signals, because the data has two maintenance paths: the
 * hand-maintained CVE range tables (NGINX_VULN_RANGES, APACHE_VULN_RANGES,
 * IIS_EOL_MAJOR), which only move when someone reviews vendor advisories and
 * bumps LOCAL_VULN_DATA_UPDATED; and the EOL cycles, which eolFetcher.ts
 * refreshes nightly on its own. Judging them together let a healthy nightly
 * fetch hide stale hand-maintained tables indefinitely.
 */
export function warnIfLocalDataStale(opts: { now?: number; log?: Pick<typeof logger, "warn" | "debug"> } = {}): void {
  // The clock and the logger default to the real ones. A caller can hand in a moment and a logger of its own, so the
  // 90-day rule can be checked at a date far from today without waiting for it.
  const now = opts.now ?? Date.now();
  const log = opts.log ?? logger;
  // The two data sets have separate maintenance paths and must be judged
  // separately. eolFetcher.ts refreshes the EOL cycles from endoflife.date
  // daily and automatically; the CVE range tables below (NGINX_VULN_RANGES,
  // APACHE_VULN_RANGES, IIS_EOL_MAJOR) are hand-maintained and only change
  // when a person reviews vendor advisories and bumps
  // LOCAL_VULN_DATA_UPDATED.
  //
  // Folding both into one "effective date" meant a successful nightly EOL
  // fetch reset the clock on the hand-maintained tables too, so the warning
  // that exists precisely to nag about them could never fire while the daily
  // job was healthy — which is exactly when nobody is looking.
  const bundledDate = new Date(LOCAL_VULN_DATA_UPDATED);
  const bundledAgeDays = Math.floor((now - bundledDate.getTime()) / 86_400_000);

  if (bundledAgeDays > LOCAL_DATA_STALE_DAYS) {
    log.warn(
      {
        bundledDate: bundledDate.toISOString(),
        ageDays: bundledAgeDays,
        staleThresholdDays: LOCAL_DATA_STALE_DAYS,
        action:
          "Review NGINX_VULN_RANGES, APACHE_VULN_RANGES and IIS_EOL_MAJOR against " +
          "current vendor advisories, then bump LOCAL_VULN_DATA_UPDATED in cveCheck.ts",
      },
      `[cveCheck] Hand-maintained CVE tables are ${bundledAgeDays} days old ` +
      `(threshold: ${LOCAL_DATA_STALE_DAYS} days). These are not refreshed by the ` +
      `nightly EOL job and require manual review against vendor advisories.`,
    );
  }

  // EOL data has its own freshness signal: the live refresh timestamp when the
  // nightly job has run, falling back to the bundled date before its first run.
  const liveDate = getEolDataFetchedAt();
  const eolDate = liveDate && liveDate > bundledDate ? liveDate : bundledDate;
  const eolSource = liveDate && liveDate > bundledDate ? "live EOL refresh" : "bundled tables";
  const eolAgeDays = Math.floor((now - eolDate.getTime()) / 86_400_000);

  if (eolAgeDays > LOCAL_DATA_STALE_DAYS) {
    log.warn(
      {
        effectiveDate: eolDate.toISOString(),
        source: eolSource,
        ageDays: eolAgeDays,
        staleThresholdDays: LOCAL_DATA_STALE_DAYS,
        action: liveDate
          ? "Check EOL refresh schedule — daily pg-boss job may be failing"
          : "Daily EOL refresh has not completed since startup",
      },
      `[cveCheck] EOL data is ${eolAgeDays} days old (threshold: ` +
      `${LOCAL_DATA_STALE_DAYS} days). Source: ${eolSource}.`,
    );
  }

  if (bundledAgeDays <= LOCAL_DATA_STALE_DAYS && eolAgeDays <= LOCAL_DATA_STALE_DAYS) {
    log.debug(
      {
        bundledDate: bundledDate.toISOString(),
        eolDate: eolDate.toISOString(),
        eolSource,
      },
      "[cveCheck] CVE/EOL data freshness OK",
    );
  }
}

// PHP EOL dates — versions that are fully end-of-life as of 2026

export function checkLocalVulns(detected: DetectedVersion[], now: Date = new Date()): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];

  for (const d of detected) {
    if (d.packageName === "php" && !d.distroPackaged) {
      // A distro PHP (8.1.2-1ubuntu2.14) is supported by the distro past upstream EOL, so
      // the upstream date says nothing about it; see bannerRules.ts.
      const major = d.version.split(".").slice(0, 1).join(".");
      const majorMinor = d.version.split(".").slice(0, 2).join(".");
      const phpEol = getLivePhpEol();
      const eolMsg = phpEol[majorMinor] || phpEol[major];
      const eol = eolMsg ? classifyEol(eolMsg, now) : null;
      if (eol?.state === "eol") {
        findings.push(vuln({
          name: `PHP ${d.version} is End-of-Life`,
          severity: "high",
          category: "Outdated Software",
          description: `PHP ${d.version} is detected in the X-Powered-By header. PHP ${d.version} is no longer receiving security patches. ${eolMsg}. Running end-of-life PHP means known vulnerabilities will never be fixed and your runtime has no security support.`,
          evidence: `X-Powered-By: PHP/${d.version}`,
          solution: `Upgrade to PHP 8.2 or PHP 8.3 (current supported releases). Plan migration carefully as major version upgrades may require code changes. See https://www.php.net/supported-versions.php`,
          cweId: "CWE-1104",
          cvssScore: 7.5,
        }));
      } else if (eol?.state === "upcoming") {
        // Still receiving security fixes today: an early warning, not a vulnerability.
        findings.push(vuln({
          name: `PHP ${d.version} Reaches End-of-Life in ${eol.label}`,
          severity: "info",
          category: "Outdated Software",
          description: `PHP ${d.version} is detected in the X-Powered-By header. This release branch still receives security fixes, but upstream support ends in ${eol.label}. Plan the upgrade before then.`,
          evidence: `X-Powered-By: PHP/${d.version}`,
          solution: `Schedule an upgrade to a PHP release with a later end-of-life date. See https://www.php.net/supported-versions.php`,
          cweId: "CWE-1104",
          cvssScore: null,
          confidence: 80,
        }));
      }
    }

    if (d.packageName === "nginx") {
      // Report the worst matching CVE only. A distro-packaged banner still gets it, as a
      // LOW "verify your package" note (see rangeFinding); EOL-cycle claims are skipped for it.
      const hit = matchRange(d.version, NGINX_VULN_RANGES);
      if (hit) {
        findings.push(vuln(rangeFinding("Nginx", d, hit, "Server", cvssToSeverity(hit.cvss))));
      } else if (!d.distroPackaged) {
        // No CVE row matched: check live EOL cycle data. Catches cycles newer than any
        // hardcoded threshold (e.g. Nginx 1.24.x).
        const nginxCycle = d.version.split(".").slice(0, 2).join(".");
        if (getLiveNginxEolCycles().has(nginxCycle)) {
          findings.push(vuln({
            name: `Nginx ${d.version} — End-of-Life Release Cycle`,
            severity: "medium",
            category: "Outdated Software",
            description:
              `Nginx ${d.version} belongs to the ${nginxCycle}.x release cycle, which has reached ` +
              `end-of-life and no longer receives security patches from the Nginx team. ` +
              `Running an unsupported Nginx version means future CVEs will not be fixed for your release.`,
            evidence: `Server: nginx/${d.version}`,
            solution:
              `Upgrade to the current Nginx stable release. ` +
              `On Debian/Ubuntu: apt upgrade nginx. On RHEL/CentOS: yum update nginx. ` +
              `See https://nginx.org/en/download.html for the latest stable version.`,
            cweId: "CWE-1104",
            cvssScore: 6.5,
          }));
        }
      }
    }

    if (d.packageName === "apache") {
      const hit = matchRange(d.version, APACHE_VULN_RANGES);
      if (hit) {
        findings.push(vuln({ ...rangeFinding("Apache HTTPD", d, hit, "Server", cvssToSeverity(hit.cvss)), wstgId: "WSTG-INFO-02" }));
      } else if (!d.distroPackaged) {
        // No CVE row matched: check live EOL cycle data. Catches EOL branches (e.g. 2.2.x).
        const apacheCycle = d.version.split(".").slice(0, 2).join(".");
        if (getLiveApacheEolCycles().has(apacheCycle)) {
          findings.push(vuln({
            name: `Apache HTTPD ${d.version} — End-of-Life Release Branch`,
            severity: "medium",
            category: "Outdated Software",
            description:
              `Apache HTTPD ${d.version} belongs to the ${apacheCycle}.x branch, which has reached ` +
              `end-of-life and no longer receives security patches from the Apache Software Foundation. ` +
              `Running an unsupported branch means future CVEs will not be addressed for your version.`,
            evidence: `Server: Apache/${d.version}`,
            solution:
              `Upgrade to the current Apache HTTPD stable release. ` +
              `On Debian/Ubuntu: apt upgrade apache2. On RHEL/CentOS: yum update httpd. ` +
              `See https://httpd.apache.org/download.cgi for the latest stable version.`,
            cweId: "CWE-1104",
            cvssScore: 6.5,
            wstgId: "WSTG-INFO-02",
          }));
        }
      }
    }

    if (d.packageName === "iis") {
      // Only flag IIS 6.x — CVE-2017-7269 is specific to IIS 6 WebDAV (Windows Server 2003)
      const majorVer = d.version.split(".")[0] ?? "";
      if (majorVer === IIS_EOL_MAJOR) {
        findings.push(vuln({
          name: `Microsoft IIS ${d.version} — CVE-2017-7269 (End-of-Life)`,
          severity: "critical",
          category: "Outdated Software",
          description: `Microsoft IIS ${d.version} is detected. IIS 6.0 (Windows Server 2003) has a critical buffer overflow vulnerability (CVE-2017-7269, CVSS 9.8) in the WebDAV service that allows remote code execution. IIS 6 reached end-of-life in July 2015 and receives no security updates.`,
          evidence: `Server: Microsoft-IIS/${d.version}`,
          solution: `Upgrade to IIS 10.0 (Windows Server 2022) or IIS 10.0 on Server 2019/2016. As an immediate mitigation, disable WebDAV in IIS if it is not required.`,
          cweId: "CWE-119",
          cvssScore: 9.8,
        }));
      }
    }
  }

  return findings;
}

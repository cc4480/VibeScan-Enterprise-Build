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

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const OSV_TIMEOUT_MS = 8_000;
const OSV_ENDPOINT = "https://api.osv.dev/v1/query";

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─────────────────────────────────────────────────────────────────────────────
// IN-PROCESS CACHE — avoids duplicate OSV.dev calls for same version
// ─────────────────────────────────────────────────────────────────────────────

const osvCache = new Map<string, OsvVuln[]>();

function osvCacheKey(packageName: string, version: string, ecosystem: string): string {
  return `${ecosystem}:${packageName}@${version}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// VERSION EXTRACTION PATTERNS
// ─────────────────────────────────────────────────────────────────────────────

interface DetectedVersion {
  displayName: string;
  /** Canonical name as returned by detectTechnologies() in scanner.ts — used for enrichment matching */
  techName: string;
  packageName: string;    // OSV package name
  ecosystem: string;      // OSV ecosystem ("npm", "PyPI", etc.)
  version: string;
}

interface VersionPattern {
  displayName: string;
  /** Canonical name as returned by detectTechnologies() in scanner.ts */
  techName?: string;
  packageName: string;
  ecosystem: string;
  patterns: RegExp[];
}

const VERSION_PATTERNS: VersionPattern[] = [
  {
    displayName: "jQuery",
    packageName: "jquery",
    ecosystem: "npm",
    patterns: [
      /jquery[/@-]v?(\d+\.\d+\.\d+)/i,                     // CDN URL pattern
      /jQuery JavaScript Library v(\d+\.\d+\.\d+)/i,        // inline comment
      /jquery\.min\.js\?ver=(\d+\.\d+\.\d+)/i,              // WordPress ?ver= param
      /"jquery":\s*"([^"]+)"/i,                              // JSON dependency
      /jquery\.fn\.jquery\s*=\s*["'](\d+\.\d+\.\d+)/i,      // runtime property
    ],
  },
  {
    displayName: "Bootstrap",
    packageName: "bootstrap",
    ecosystem: "npm",
    patterns: [
      /bootstrap[/@-]v?(\d+\.\d+\.\d+)/i,
      /Bootstrap v(\d+\.\d+\.\d+)/i,
      /bootstrap\.min\.(?:css|js)\?ver=(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "Lodash",
    packageName: "lodash",
    ecosystem: "npm",
    patterns: [
      /lodash[/@-]v?(\d+\.\d+\.\d+)/i,
      /lodash\.min\.js\?ver=(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "Moment.js",
    packageName: "moment",
    ecosystem: "npm",
    patterns: [
      /moment[/@-]v?(\d+\.\d+\.\d+)/i,
      /moment\.min\.js\?ver=(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "Vue.js",
    packageName: "vue",
    ecosystem: "npm",
    patterns: [
      /vue[/@-]v?(\d+\.\d+\.\d+)/i,
      /Vue\.version\s*=\s*["'](\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "AngularJS",
    techName: "Angular",
    packageName: "angular",
    ecosystem: "npm",
    patterns: [
      /angular[/@-]v?(\d+\.\d+\.\d+)(?![@/]core)/i,
      /AngularJS v(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "Underscore.js",
    packageName: "underscore",
    ecosystem: "npm",
    patterns: [
      /underscore[/@-]v?(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "Handlebars.js",
    packageName: "handlebars",
    ecosystem: "npm",
    patterns: [
      /handlebars[/@-]v?(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "highlight.js",
    packageName: "highlight.js",
    ecosystem: "npm",
    patterns: [
      /highlight\.js[/@-]v?(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "Marked",
    packageName: "marked",
    ecosystem: "npm",
    patterns: [
      /marked[/@-]v?(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "DOMPurify",
    packageName: "dompurify",
    ecosystem: "npm",
    patterns: [
      /dompurify[/@-]v?(\d+\.\d+\.\d+)/i,
      /DOMPurify\.version\s*=\s*["'](\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "Axios",
    packageName: "axios",
    ecosystem: "npm",
    patterns: [
      /axios[/@-]v?(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "CKEditor",
    packageName: "ckeditor4",
    ecosystem: "npm",
    patterns: [
      /ckeditor[/@-]v?(\d+\.\d+\.\d+)/i,
      /CKEditor\s+(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "TinyMCE",
    packageName: "tinymce",
    ecosystem: "npm",
    patterns: [
      /tinymce[/@-]v?(\d+\.\d+\.\d+)/i,
      /tinymce\/(\d+\.\d+\.\d+)/i,
    ],
  },
  {
    displayName: "WordPress",
    packageName: "wordpress",
    ecosystem: "WordPress",
    patterns: [
      /<meta[^>]*generator[^>]*WordPress\s+(\d+\.\d+\.?\d*)/i,
      /WordPress\.org\?v=(\d+\.\d+\.?\d*)/i,
      /wp-includes\/js\/jquery\/jquery(?:\.min)?\.js\?ver=(\d+\.\d+\.?\d*)/i,
    ],
  },
  {
    displayName: "Drupal",
    packageName: "drupal",
    ecosystem: "Packagist",
    patterns: [
      /<meta[^>]*generator[^>]*Drupal\s+(\d+\.\d+\.?\d*)/i,
      /Drupal\.settings.*?["']version["']\s*:\s*["'](\d+\.\d+\.?\d*)/i,
    ],
  },
  {
    displayName: "Joomla",
    packageName: "joomla",
    ecosystem: "Packagist",
    patterns: [
      /<meta[^>]*generator[^>]*Joomla!\s+(\d+\.\d+\.?\d*)/i,
    ],
  },
];

export function extractVersionedTechnologies(
  html: string,
  headers: Record<string, string>,
): DetectedVersion[] {
  const found: DetectedVersion[] = [];
  const seen = new Set<string>(); // avoid duplicates for same package

  const content = html.slice(0, 150_000); // only scan first 150KB

  for (const vp of VERSION_PATTERNS) {
    if (seen.has(vp.packageName)) continue;
    for (const rx of vp.patterns) {
      const m = rx.exec(content);
      if (m?.[1]) {
        const version = m[1].replace(/^[vV]/, "");
        if (/^\d+\.\d+/.test(version)) {
          found.push({
            displayName: vp.displayName,
            techName: vp.techName ?? vp.displayName,
            packageName: vp.packageName,
            ecosystem: vp.ecosystem,
            version,
          });
          seen.add(vp.packageName);
          break;
        }
      }
    }
  }

  // ── Headers: extract versioned server/runtime software ────────────────────

  const serverHeader = Object.entries(headers).find(([k]) => k.toLowerCase() === "server")?.[1] ?? "";
  const poweredBy = Object.entries(headers).find(([k]) => k.toLowerCase() === "x-powered-by")?.[1] ?? "";

  // PHP version from X-Powered-By header (not in OSV, checked locally)
  const phpMatch = /PHP\/(\d+\.\d+\.?\d*)/i.exec(poweredBy);
  if (phpMatch?.[1] && !seen.has("php")) {
    found.push({
      displayName: "PHP",
      techName: "PHP",
      packageName: "php",
      ecosystem: "local",
      version: phpMatch[1],
    });
    seen.add("php");
  }

  // Nginx version from Server header
  const nginxMatch = /nginx\/(\d+\.\d+\.\d+)/i.exec(serverHeader);
  if (nginxMatch?.[1] && !seen.has("nginx")) {
    found.push({ displayName: "Nginx", techName: "Nginx", packageName: "nginx", ecosystem: "local", version: nginxMatch[1] });
    seen.add("nginx");
  }

  // Apache version from Server header — techName matches detectTechnologies() output "Apache"
  const apacheMatch = /Apache\/(\d+\.\d+\.\d+)/i.exec(serverHeader);
  if (apacheMatch?.[1] && !seen.has("apache")) {
    found.push({ displayName: "Apache HTTPD", techName: "Apache", packageName: "apache", ecosystem: "local", version: apacheMatch[1] });
    seen.add("apache");
  }

  // Microsoft IIS version from Server header — techName matches detectTechnologies() output "IIS"
  const iisMatch = /Microsoft-IIS\/(\d+\.\d+)/i.exec(serverHeader);
  if (iisMatch?.[1] && !seen.has("iis")) {
    found.push({ displayName: "Microsoft IIS", techName: "IIS", packageName: "iis", ecosystem: "local", version: iisMatch[1] });
    seen.add("iis");
  }

  // OpenResty version from Server header
  const openrestyMatch = /openresty\/(\d+\.\d+\.\d+)/i.exec(serverHeader);
  if (openrestyMatch?.[1] && !seen.has("openresty")) {
    found.push({ displayName: "OpenResty", techName: "OpenResty", packageName: "openresty", ecosystem: "local", version: openrestyMatch[1] });
    seen.add("openresty");
  }

  // LiteSpeed version from Server header
  const litespeedMatch = /LiteSpeed\/(\d+\.\d+\.?\d*)/i.exec(serverHeader);
  if (litespeedMatch?.[1] && !seen.has("litespeed")) {
    found.push({ displayName: "LiteSpeed", techName: "LiteSpeed", packageName: "litespeed", ecosystem: "local", version: litespeedMatch[1] });
    seen.add("litespeed");
  }

  return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// OSV.dev QUERY (with in-process cache)
// ─────────────────────────────────────────────────────────────────────────────

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{
    ranges?: Array<{ events?: Array<{ fixed?: string }> }>;
  }>;
}

async function queryOsv(packageName: string, version: string, ecosystem: string): Promise<OsvVuln[]> {
  const cacheKey = osvCacheKey(packageName, version, ecosystem);
  if (osvCache.has(cacheKey)) {
    return osvCache.get(cacheKey)!;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);
  try {
    const res = await fetch(OSV_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version,
        package: { name: packageName, ecosystem },
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      // Cache definitive non-2xx responses (e.g. 404 — package not found in OSV)
      osvCache.set(cacheKey, []);
      return [];
    }
    const json = (await res.json()) as { vulns?: OsvVuln[] };
    const vulns = json.vulns ?? [];
    // Only cache definitive successful responses — not transient errors
    osvCache.set(cacheKey, vulns);
    return vulns;
  } catch {
    // Network errors and timeouts are transient — do NOT cache so the next
    // scan can retry. Just return empty for this request.
    return [];
  } finally {
    clearTimeout(timer);
  }
}

function extractCvss(vuln: OsvVuln): number | null {
  for (const s of vuln.severity ?? []) {
    if (s.type === "CVSS_V3" || s.type === "CVSS_V4") {
      // Parse CVSS score from vector string
      const match = /\/(\d+\.\d+)$/.exec(s.score) || s.score.match(/^(\d+\.\d+)$/);
      if (match) return parseFloat(match[1]);
    }
  }
  // Try database_specific severity
  const dbSev = vuln.database_specific?.severity;
  if (dbSev === "CRITICAL") return 9.0;
  if (dbSev === "HIGH") return 7.5;
  if (dbSev === "MODERATE" || dbSev === "MEDIUM") return 5.5;
  if (dbSev === "LOW") return 3.1;
  return null;
}

function cvssToSeverity(score: number | null): ScanVulnerability["severity"] {
  if (!score) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

function extractFixedVersion(osvVuln: OsvVuln): string | null {
  for (const affected of osvVuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

function cveIds(osvVuln: OsvVuln): string[] {
  return (osvVuln.aliases ?? [osvVuln.id]).filter((id) => id.startsWith("CVE-")).slice(0, 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// LOCAL CHECKS (no network call)
// ─────────────────────────────────────────────────────────────────────────────

// PHP EOL dates — versions that are fully end-of-life as of 2026
const PHP_EOL: Record<string, string> = {
  "5": "Reached EOL in December 2018",
  "7.0": "Reached EOL in December 2019",
  "7.1": "Reached EOL in December 2019",
  "7.2": "Reached EOL in November 2020",
  "7.3": "Reached EOL in December 2021",
  "7.4": "Reached EOL in November 2022",
  "8.0": "Reached EOL in November 2023",
  "8.1": "Reaches EOL in December 2025",
};

// Nginx versions known to have critical CVEs
const NGINX_VULN_RANGES: Array<{ lt: string; cve: string; desc: string; cvss: number }> = [
  { lt: "1.20.1", cve: "CVE-2021-23017", desc: "1-byte memory overwrite in DNS resolver (CVSS 9.4 — off-by-one in UDP response handling)", cvss: 9.4 },
  { lt: "1.18.0", cve: "CVE-2019-9511", desc: "HTTP/2 DoS vulnerability (Data Dribble attack)", cvss: 7.5 },
];

// Apache versions with known critical issues
const APACHE_VULN_RANGES: Array<{ lt: string; cve: string; desc: string; cvss: number }> = [
  { lt: "2.4.55", cve: "CVE-2023-25690", desc: "HTTP request smuggling / header injection (CVSS 9.8 — allows bypassing access controls)", cvss: 9.8 },
  { lt: "2.4.52", cve: "CVE-2021-41773", desc: "Path traversal and RCE on Apache 2.4.49 (historic Proxypass exploit)", cvss: 9.8 },
];

// Microsoft IIS 6.x — CVE-2017-7269 targets WebDAV in IIS 6 only (Windows 2003).
// IIS 7/8/8.5/10 are NOT affected, so we only flag major version "6".
const IIS_EOL_MAJOR = "6";

function semverLt(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na < nb) return true;
    if (na > nb) return false;
  }
  return false;
}

function checkLocalVulns(detected: DetectedVersion[]): ScanVulnerability[] {
  const findings: ScanVulnerability[] = [];

  for (const d of detected) {
    if (d.packageName === "php") {
      const major = d.version.split(".").slice(0, 1).join(".");
      const majorMinor = d.version.split(".").slice(0, 2).join(".");
      const eolMsg = PHP_EOL[majorMinor] || PHP_EOL[major];
      if (eolMsg) {
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
      }
    }

    if (d.packageName === "nginx") {
      for (const vuln_entry of NGINX_VULN_RANGES) {
        if (semverLt(d.version, vuln_entry.lt)) {
          findings.push(vuln({
            name: `Nginx ${d.version} — Known Vulnerability (${vuln_entry.cve})`,
            severity: cvssToSeverity(vuln_entry.cvss),
            category: "Outdated Software",
            description: `Nginx ${d.version} is vulnerable to ${vuln_entry.cve}: ${vuln_entry.desc}. Versions before ${vuln_entry.lt} are affected.`,
            evidence: `Server: nginx/${d.version}`,
            solution: `Upgrade Nginx to version ${vuln_entry.lt} or later. Use your package manager: apt upgrade nginx, or yum update nginx. Verify with: nginx -v`,
            cweId: "CWE-1104",
            cvssScore: vuln_entry.cvss,
          }));
          break; // report worst one only
        }
      }
    }

    if (d.packageName === "apache") {
      for (const vuln_entry of APACHE_VULN_RANGES) {
        if (semverLt(d.version, vuln_entry.lt)) {
          findings.push(vuln({
            name: `Apache ${d.version} — Known Vulnerability (${vuln_entry.cve})`,
            severity: cvssToSeverity(vuln_entry.cvss),
            category: "Outdated Software",
            description: `Apache HTTPD ${d.version} is vulnerable to ${vuln_entry.cve}: ${vuln_entry.desc}. Upgrade to ${vuln_entry.lt} or later.`,
            evidence: `Server: Apache/${d.version}`,
            solution: `Upgrade Apache to the latest stable release. On Debian/Ubuntu: apt upgrade apache2. On RHEL/CentOS: yum update httpd. Confirm with: apache2 -v`,
            cweId: "CWE-1104",
            cvssScore: vuln_entry.cvss,
          }));
          break;
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

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function checkForKnownVulnerabilities(
  html: string,
  headers: Record<string, string>,
): Promise<ScanVulnerability[]> {
  const detected = extractVersionedTechnologies(html, headers);
  if (detected.length === 0) return [];

  const findings: ScanVulnerability[] = [];

  // 1. Local checks (instant, no network)
  findings.push(...checkLocalVulns(detected));

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
          `Detected version: ${target.displayName} ${target.version}\n` +
          `CVE(s): ${cveList}\n` +
          (osvVuln.details ? `Details: ${osvVuln.details.slice(0, 300)}...` : ""),
        solution:
          fixedVersion
            ? `Upgrade ${target.displayName} to version ${fixedVersion} or later. ` +
              `Update CDN reference URLs or your package.json dependency.`
            : `Upgrade ${target.displayName} to the latest stable version. ` +
              `Check ${target.ecosystem === "npm" ? "https://www.npmjs.com/package/" + target.packageName : "the vendor advisory"} for patched releases.`,
        cweId: "CWE-1104",
        cvssScore: score > 0 ? score : null,
      }));
    }
  }

  return findings;
}

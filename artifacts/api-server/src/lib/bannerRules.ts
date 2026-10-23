/**
 * Rules for turning a version banner (Server / X-Powered-By) into a finding.
 *
 * A banner says what a server CLAIMS to be, not what it runs. Three things follow, and each was
 * a false positive before this module existed:
 *
 *  1. EOL is a date. "Reaches EOL in December 2026" is an early warning today, not "is
 *     End-of-Life", so the wording in the EOL tables is parsed against the current date.
 *  2. Distro packages backport security fixes without changing the upstream version, so
 *     `nginx/1.24.0 (Ubuntu)` or `PHP/8.1.2-1ubuntu2.14` cannot be judged against upstream
 *     fix versions or upstream EOL. Those match at most a LOW "verify your package" note.
 *  3. A version below a fix release is applicable only where the vulnerable feature is
 *     configured (resolver, ProxyPassReverseCookie*, HTTP/2 ...). A banner cannot show that.
 */

import type { ScanVulnerability } from "./scanner";
import type { VulnRange } from "./cve-patterns";

export type EolState = "eol" | "upcoming" | "unknown";

const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];

/**
 * Classify an EOL table entry ("Reached EOL in November 2023" / "Reaches EOL in December 2026")
 * against `now`. The date decides, not the tense of the sentence: the entry may have been
 * written (or persisted by the nightly refresh) before or after the date passed. A month-only
 * date is taken to end on the month's last day, so a cycle is never called EOL early.
 */
export function classifyEol(message: string, now: Date = new Date()): { state: EolState; label: string } {
  const m = /EOL in ([A-Za-z]+) (\d{4})/.exec(message);
  const month = m ? MONTHS.indexOf(m[1]!.toLowerCase()) : -1;
  if (!m || month < 0) return { state: "unknown", label: message };
  const year = Number(m[2]);
  const endOfMonth = Date.UTC(year, month + 1, 1) - 1;
  return { state: now.getTime() > endOfMonth ? "eol" : "upcoming", label: `${m[1]} ${year}` };
}

/** Distribution vendors whose packages carry backported fixes; from the Server comment. */
const DISTRO_COMMENT = /\((?:[^)]*\b)?(?:Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|Amazon|SUSE|openSUSE|Rocky|Alma|Oracle|Raspbian|Kali)\b[^)]*\)/i;
/** Package-release suffixes on the version itself: 8.1.2-1ubuntu2.14, 8.2.7-1~deb12u1, 8.0.30-1.el9. */
const DISTRO_SUFFIX = /ubuntu|[~+.]deb\d|\.el\d|\.amzn|\.fc\d|\.suse|\.centos|\.rocky|\.alma/i;

/** `rest` is whatever follows the numeric version in the header value. */
export function isDistroPackaged(rest: string): boolean {
  return DISTRO_COMMENT.test(rest) || DISTRO_SUFFIX.test(rest.split(/\s/)[0] ?? "");
}

export function semverLt(a: string, b: string): boolean {
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

/** First row (tables are ordered worst-first) whose [gte, lt) range holds `version`. */
export function matchRange(version: string, ranges: VulnRange[]): VulnRange | undefined {
  return ranges.find((r) => (!r.gte || !semverLt(version, r.gte)) && semverLt(version, r.lt));
}

const RANK = ["info", "low", "medium", "high", "critical"] as const;
type Sev = (typeof RANK)[number];
const capSeverity = (s: Sev, cap: Sev): Sev => (RANK.indexOf(s) > RANK.indexOf(cap) ? cap : s);

/**
 * Finding for a banner that falls in a CVE's affected range. It states only what was observed
 * (the banner and the fix version), never that the server "is vulnerable":
 *  - distro-packaged: LOW, low confidence, "verify your package" (backports make the version moot);
 *  - configuration-dependent: capped at MEDIUM, "applies only if <requires>";
 *  - otherwise the CVSS-derived severity with moderate confidence.
 */
export function rangeFinding(
  product: string,
  d: { version: string; distroPackaged?: boolean },
  r: VulnRange,
  header: string,
  cvssSeverity: Sev,
): Omit<ScanVulnerability, "id"> {
  const shown = `${product} ${d.version}`;
  const observed = `The ${header} header reports ${shown}, which is older than ${r.lt}, the release that fixes ${r.cve}: ${r.desc}.`;
  const untested = "This is a banner-only match; the scanner did not test the flaw.";
  const applies = r.requires ? ` It applies only if ${r.requires}.` : "";
  if (d.distroPackaged) {
    return {
      name: `${shown} — Verify Distro Package Against ${r.cve}`,
      severity: "low",
      category: "Outdated Software",
      description: `${observed} ${untested} The banner identifies a distribution package, and distributions backport security fixes without changing the upstream version number, so a version below ${r.lt} does not show the fix is missing.${applies}`,
      evidence: `${header}: ${product}/${d.version} (distro-packaged)`,
      solution: `Check the installed package's changelog for ${r.cve} (Debian/Ubuntu: apt changelog <package> | grep ${r.cve}; RHEL family: rpm -q --changelog <package> | grep ${r.cve}) and apply pending updates. No action is needed if the changelog lists the fix.`,
      cweId: "CWE-1104",
      cvssScore: null,
      confidence: 25,
    };
  }
  return {
    name: `${shown} — Version Below Fix for ${r.cve}`,
    severity: r.requires ? capSeverity(cvssSeverity, "medium") : cvssSeverity,
    category: "Outdated Software",
    description: `${observed} ${untested}${applies}`,
    evidence: `${header}: ${product}/${d.version}`,
    solution: `Upgrade ${product} to ${r.lt} or later, or confirm that your build carries a backported fix. Use your package manager (apt upgrade / dnf update) and verify the running version.`,
    cweId: "CWE-1104",
    cvssScore: r.cvss,
    confidence: r.requires ? 40 : 60,
  };
}

import type { ScanResult } from "./scanner";
import type { ReconRunResult } from "./workerTypes";
import { and } from "drizzle-orm";
import { computeRiskScore, gradeForResult } from "./scanner";
import { type TestRecord } from "./testLedger";
import { analyseFindings } from "./aiAnalysis";
import { summariseCompliance, COMPLIANCE_DISCLAIMER } from "./compliance";
import { probeCertDates } from "./monitorPulseCert";
import { splitScanNotes } from "./scanNotes";

function buildExecutiveSummary(
  grade: string,
  riskScore: number,
  targetUrl: string,
  totalVulns: number,
  counts: Record<string, number>,
): string {
  const domain = (() => {
    try { return new URL(targetUrl).hostname; } catch { return targetUrl; }
  })();

  const critical = counts["critical"] ?? 0;
  const high = counts["high"] ?? 0;

  if (totalVulns === 0) {
    // Not "passed all security checks": a scan with skipped tests has not checked those areas,
    // and a clean grade says nothing about them. The report's coverage section lists them.
    return `${domain} has a grade of ${grade}: the tests that ran found no significant vulnerabilities. That is not a statement about any area this scan did not test, which the report lists. Re-scan regularly.`;
  }

  const urgencyPhrase =
    critical > 0
      ? `${critical} critical issue${critical > 1 ? "s" : ""} requiring immediate attention`
      : high > 0
        ? `${high} high-severity issue${high > 1 ? "s" : ""} that should be addressed promptly`
        : `${totalVulns} security finding${totalVulns > 1 ? "s" : ""}, none of them critical or high`;
  const advice = critical + high > 0 ? " Review the findings below and fix the critical and high items first." : "";

  return `Security scan of ${domain} identified ${urgencyPhrase}, yielding an overall grade of ${grade} with a risk score of ${riskScore}/100.${advice}`;
}

/** Scores, grades and assembles the stored report for a finished scan. */
export async function buildReport(input: {
  scanResult: ScanResult;
  targetUrl: string;
  tests: TestRecord[];
  reconRunResult: ReconRunResult;
  aiAnalysis: Awaited<ReturnType<typeof analyseFindings>>["analysis"] | null;
  autoSuppressedCount: number;
}) {
  const { scanResult, targetUrl, tests, reconRunResult, aiAnalysis, autoSuppressedCount } = input;
  const riskScore = computeRiskScore(scanResult.vulnerabilities);
  // A scan a bot-protection layer answered must NOT be graded — see
  // gradeForResult. The score stays computed and stored for the record; the
  // grade becomes the sentinel the report and dashboard render as "coverage
  // incomplete".
  const intercepted = scanResult.intercepted;
  const grade = gradeForResult(riskScore, intercepted);

  // The scan's own notes stay in the stored list, so they travel with the report, but they are not
  // findings about the site: none of the counts below includes them (see scanNotes.ts). They are Info,
  // which carries no weight in the score, so the score above does not need telling them apart.
  const { findings } = splitScanNotes(scanResult.vulnerabilities);
  const severityCounts = findings.reduce(
    (acc, v) => {
      acc[v.severity] = (acc[v.severity] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const interceptionKind = scanResult.interception?.kind ?? "bot challenge";
  const executiveSummary = intercepted
    ? `The scan of ${(() => { try { return new URL(targetUrl).hostname; } catch { return targetUrl; } })()} ` +
      (interceptionKind === "sign-in wall"
        ? `reached a sign-in page${scanResult.interception?.vendor ? ` run by ${scanResult.interception.vendor}` : ""} rather than the app, so no grade could be assigned. `
        : interceptionKind === "app not running"
          ? `was answered by ${scanResult.interception?.vendor ?? "the hosting platform"}'s own page rather than a running app, so no grade could be assigned. `
          : `was answered by a bot-protection layer rather than the site itself, so no grade could be assigned. `) +
      `Only the checks that do not read the page response — DNS, email authentication and mail transport — ` +
      `are reported below and are accurate; everything else was withheld and is listed as withheld. This is an incomplete result, not a ` +
      `clean one. ` +
      (interceptionKind === "sign-in wall"
        ? `To grade the app, scan an address that serves it without signing in, or supply a login for the scan.`
        : interceptionKind === "app not running"
          ? `Check that the app is deployed and running at this address, then re-scan.`
          : `To grade the site, allow the scanner through the challenge (by source IP or User-Agent) or verify domain ownership, then re-scan.`)
    : buildExecutiveSummary(
        grade,
        riskScore,
        targetUrl,
        findings.length,
        severityCounts,
      );

  // Probe TLS cert expiry for https:// targets (non-blocking, failures are soft)
  const cert = await probeCertDates(scanResult.finalUrl || targetUrl).catch(() => null);

  const reportData = {
    targetUrl: scanResult.finalUrl || targetUrl,
    vulnerabilities: scanResult.vulnerabilities,
    technologies: scanResult.technologies,
    server: scanResult.server,
    tlsGrade: scanResult.tlsGrade,
    certExpiry: cert ? cert.expiresAt.toISOString() : null,
    // Lets the expiry alert skip its 30-day warning for an auto-renewing (short-lived) certificate.
    certIssuedAt: cert?.issuedAt ? cert.issuedAt.toISOString() : null,
    pagesScanned: scanResult.pagesScanned,
    probedNotFound: scanResult.probedNotFound,
    // What ran, what was skipped and why — so the report can show coverage,
    // not just findings. See testLedger.ts.
    tests,
    // Findings the scan produced and did not report, with the reason, and what answered instead of
    // the app when something did. Shown in the report so nothing is dropped out of sight.
    withheld: scanResult.withheld && scanResult.withheld.length > 0 ? scanResult.withheld : undefined,
    interception: scanResult.interception ?? undefined,
    summary: {
      totalVulnerabilities: findings.length,
      critical: severityCounts["critical"] ?? 0,
      high: severityCounts["high"] ?? 0,
      medium: severityCounts["medium"] ?? 0,
      low: severityCounts["low"] ?? 0,
      info: severityCounts["info"] ?? 0,
      riskScore,
      grade,
      intercepted,
      executiveSummary,
    },
    recon: reconRunResult?.recon ?? undefined,
    aiAnalysis: aiAnalysis ?? undefined,
    // Which controls these findings are evidence FOR — not a compliance verdict.
    // Computed here so the mapping is frozen into the stored report alongside the
    // findings it describes: re-deriving it at render time would let a later
    // change to the mapping silently restate what an already-delivered report
    // said. See lib/compliance.ts, and COMPLIANCE_DISCLAIMER, which any view of
    // this data must carry.
    compliance: {
      frameworks: summariseCompliance(scanResult.vulnerabilities),
      disclaimer: COMPLIANCE_DISCLAIMER,
    },
    autoSuppressedCount: autoSuppressedCount > 0 ? autoSuppressedCount : undefined,
  };
  return { reportData, riskScore, grade, intercepted, severityCounts, executiveSummary };
}

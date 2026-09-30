import type { ScanResult } from "./scanner";
import type { ReconRunResult } from "./workerTypes";
import { and } from "drizzle-orm";
import { computeRiskScore, gradeForResult } from "./scanner";
import { type TestRecord } from "./testLedger";
import { analyseFindings } from "./aiAnalysis";
import { summariseCompliance, COMPLIANCE_DISCLAIMER } from "./compliance";
import * as tls from "node:tls";

/** Probe the TLS certificate expiry date for an https:// URL. Returns null for HTTP or on error. */
async function getCertExpiry(url: string): Promise<Date | null> {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return null;
    const host = parsed.hostname;
    const port = parseInt(parsed.port || "443", 10);
    return await new Promise<Date | null>((resolve) => {
      const socket = tls.connect(
        { host, port, servername: host, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          if (!cert || !cert.valid_to) { resolve(null); return; }
          resolve(new Date(cert.valid_to));
        },
      );
      socket.on("error", () => resolve(null));
      socket.setTimeout(8_000, () => { socket.destroy(); resolve(null); });
    });
  } catch {
    return null;
  }
}

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

  const severityCounts = scanResult.vulnerabilities.reduce(
    (acc, v) => {
      acc[v.severity] = (acc[v.severity] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const executiveSummary = intercepted
    ? `The scan of ${(() => { try { return new URL(targetUrl).hostname; } catch { return targetUrl; } })()} ` +
      `was answered by a bot-protection layer rather than the site itself, so no grade could be assigned. ` +
      `Only the checks that do not read the page response — DNS, email authentication and mail transport — ` +
      `are reported below and are accurate; everything else was withheld. This is an incomplete result, not a ` +
      `clean one. To grade the site, allow the scanner through the challenge (by source IP or User-Agent) or ` +
      `verify domain ownership, then re-scan.`
    : buildExecutiveSummary(
        grade,
        riskScore,
        targetUrl,
        scanResult.vulnerabilities.length,
        severityCounts,
      );

  // Probe TLS cert expiry for https:// targets (non-blocking, failures are soft)
  const certExpiry = await getCertExpiry(scanResult.finalUrl || targetUrl).catch(() => null);

  const reportData = {
    targetUrl: scanResult.finalUrl || targetUrl,
    vulnerabilities: scanResult.vulnerabilities,
    technologies: scanResult.technologies,
    server: scanResult.server,
    tlsGrade: scanResult.tlsGrade,
    certExpiry: certExpiry ? certExpiry.toISOString() : null,
    pagesScanned: scanResult.pagesScanned,
    probedNotFound: scanResult.probedNotFound,
    // What ran, what was skipped and why — so the report can show coverage,
    // not just findings. See testLedger.ts.
    tests,
    summary: {
      totalVulnerabilities: scanResult.vulnerabilities.length,
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

import type { ScanResult } from "./scanner";
import type { Log, SslLabsResult, ReconRunResult, LiveProgress } from "./workerTypes";
import { and } from "drizzle-orm";
import { type ScanVulnerability } from "./scanner";
import { formatTestLine, formatTestSummary, foundNames, NOT_VERIFIED, type TestRecord } from "./testLedger";
import { tlsFindings, tlsHeadline, tlsSummary } from "./tlsCheckFindings";
import type { TlsInspection } from "./tlsCheckTypes";
import { randomUUID } from "node:crypto";

/**
 * Whether to ask the Qualys SSL Labs API about the target. Off unless SSLLABS_ENABLED=true: Qualys's
 * terms require their permission for commercial use of the API (and v3, which ssllabs.ts calls, was
 * deprecated in 2024), so an operator who has that permission opts in. The scanner's own TLS
 * configuration check (tlsCheck.ts) runs either way.
 */
export function sslLabsEnabled(): boolean {
  return process.env["SSLLABS_ENABLED"] === "true";
}

/**
 * Why the TLS grade is below A, as an informational finding, so the cover's grade always has its
 * reason beside it. States only what SSL Labs reported; says so when it reported nothing specific.
 */
export function tlsGradeNote(r: NonNullable<SslLabsResult>): ScanVulnerability {
  const known = r.reasons.length > 0;
  return {
    id: randomUUID(),
    name: "TLS Grade Below A (SSL Labs)",
    severity: "info",
    category: "Transport Security",
    description: known
      ? `SSL Labs graded this site's TLS configuration ${r.grade}, not A. What held it back: ${r.reasons.join(" ")}`
      : `SSL Labs graded this site's TLS configuration ${r.grade}, not A. Its response did not name a specific cause, so none is guessed here. The full SSL Labs report lists the exact reason.`,
    evidence: [`SSL Labs grade: ${r.grade}`, ...r.reasons, r.reportUrl ? `Full report: ${r.reportUrl}` : null].filter(Boolean).join("\n"),
    solution: "Disable TLS 1.0 and 1.1, keep TLS 1.2 and 1.3 with forward-secret cipher suites, and re-run the SSL Labs test to confirm. Mozilla's SSL Configuration Generator gives settings per server.",
    cweId: "CWE-326",
    cvssScore: 0,
    confidence: 90,
  } satisfies ScanVulnerability;
}

/**
 * Folds the SSL Labs grade into the scan: sets the TLS grade the report shows and adds a weak-TLS
 * finding. Called only when SSL Labs is enabled (sslLabsEnabled). With it off the report carries no
 * grade at all, and the scanner's own TLS check supplies the TLS findings.
 */
export function mergeSslLabs(scanResult: ScanResult, sslLabsResult: SslLabsResult, log: Log): void {
  if (sslLabsResult) {
    log.info({ grade: sslLabsResult.grade, issues: sslLabsResult.issues.length }, "SSL Labs assessment complete");
    // The only source of a TLS grade: the scan itself measures none
    scanResult.tlsGrade = sslLabsResult.grade;

    // Add SSL Labs findings as vulnerabilities
    if (sslLabsResult.grade && /^[C-F]$/.test(sslLabsResult.grade)) {
      scanResult.vulnerabilities.push({
        id: randomUUID(),
        name: `Weak TLS Configuration (SSL Labs Grade: ${sslLabsResult.grade})`,
        severity: sslLabsResult.grade === "F" ? "critical" : sslLabsResult.grade === "D" ? "high" : "medium",
        category: "Transport Security",
        description: `SSL Labs graded your TLS configuration as ${sslLabsResult.grade}. This indicates weak cipher suites, outdated protocol support, or certificate issues that could expose users to downgrade attacks.`,
        evidence: [...sslLabsResult.issues, ...sslLabsResult.reasons].join("; ") || null,
        solution: "Use a modern TLS configuration: TLS 1.2 minimum, TLS 1.3 preferred, disable RC4/3DES/CBC-mode cipher suites, and enable HSTS. Use Mozilla's SSL Configuration Generator for server-specific settings.",
        cweId: "CWE-326",
        cvssScore: sslLabsResult.grade === "F" ? 9.1 : sslLabsResult.grade === "D" ? 7.5 : 5.3,
      } satisfies ScanVulnerability);
    }

    // A B or A- is not a defect to fix, but a grade with no explanation is a claim with no basis.
    if (sslLabsResult.grade && /^A-$|^B$/.test(sslLabsResult.grade)) {
      scanResult.vulnerabilities.push(tlsGradeNote(sslLabsResult));
    }
  } else {
    log.warn("SSL Labs assessment not available — this report carries no SSL Labs grade");
  }
}

/** The scanner's own TLS configuration check, with the findings it raised. */
export interface TlsCheckRun {
  inspection: TlsInspection;
  findings: ScanVulnerability[];
}

/** The ledger's name for the check; the record's name adds a short summary in brackets. */
export const TLS_CHECK_TEST = "TLS configuration check";

/** Folds the TLS configuration check into the scan as first-class findings. */
export function mergeTlsCheck(scanResult: ScanResult, inspection: TlsInspection, log: Log, now: Date = new Date()): TlsCheckRun {
  if (inspection.status !== "inspected") {
    const line = { reason: inspection.reason };
    if (inspection.status === "failed") log.warn(line, "TLS configuration check could not complete");
    else log.info(line, "TLS configuration check skipped");
    return { inspection, findings: [] };
  }
  const findings = tlsFindings(inspection.result, now);
  scanResult.vulnerabilities.push(...findings);
  log.info({ findings: findings.length }, `TLS configuration check complete: ${tlsSummary(inspection.result, now)}`);
  return { inspection, findings };
}

/** The ledger record for the TLS configuration check: what ran, what was skipped, what could not be done. */
export function tlsCheckRecord(run: TlsCheckRun, durationMs: number, now: Date = new Date()): TestRecord {
  const { inspection, findings } = run;
  if (inspection.status === "inspected") {
    return {
      group: "transport",
      name: `${TLS_CHECK_TEST} (${tlsHeadline(inspection.result, now)})`,
      status: "ran",
      findings: findings.length,
      durationMs,
      ...(findings.length > 0 ? { found: foundNames(findings) } : {}),
    };
  }
  return { group: "transport", name: TLS_CHECK_TEST, status: inspection.status, findings: 0, durationMs, reason: inspection.reason };
}

/** Folds reconnaissance (dangerous ports) into the scan as first-class findings. */
export function mergeRecon(scanResult: ScanResult, reconRunResult: ReconRunResult, log: Log): void {
  if (reconRunResult) {
    // Dangerous-port findings surface as first-class vulnerabilities
    scanResult.vulnerabilities.push(...reconRunResult.vulns);
    log.info(
      {
        portVulns: reconRunResult.vulns.length,
        openPorts: reconRunResult.recon.openPorts.length,
        subdomains: reconRunResult.recon.subdomains.length,
        dnsRecords: reconRunResult.recon.dnsRecords.length,
      },
      "Recon complete — merged into scan result",
    );
  } else {
    log.warn("Recon results unavailable — continuing without reconnaissance data");
  }
}

/**
 * Everything the scan was meant to run — the scanner's own ledger plus the TLS check, SSL Labs
 * (when enabled) and reconnaissance, which run beside it — each with its outcome, sent live and
 * logged one line per test.
 */
export async function recordSideTests(input: {
  scanResult: ScanResult;
  sslLabsEnabled: boolean;
  sslLabsResult: SslLabsResult;
  tlsCheck: TlsCheckRun;
  reconRunResult: ReconRunResult;
  allowActiveProbes: boolean;
  parallelStartedAt: number;
  live: LiveProgress;
  log: Log;
}): Promise<TestRecord[]> {
  const { scanResult, sslLabsEnabled: sslLabsOn, sslLabsResult, tlsCheck, reconRunResult, allowActiveProbes, parallelStartedAt, live, log } = input;
  const tests: TestRecord[] = [...(scanResult.tests ?? [])];
  const sideMs = Date.now() - parallelStartedAt;
  tests.push(tlsCheckRecord(tlsCheck, sideMs));
  // With SSL Labs off (the default) there is no such test to report, rather than a failed one.
  if (sslLabsOn) {
    tests.push(
      sslLabsResult
        ? { group: "transport", name: `SSL Labs TLS grade (${sslLabsResult.grade ?? "no grade"})`, status: "ran", findings: sslLabsResult.grade && /^(?:[C-F]|A-|B)$/.test(sslLabsResult.grade) ? 1 : 0, durationMs: sideMs }
        : { group: "transport", name: "SSL Labs TLS grade", status: "failed", findings: 0, durationMs: sideMs, reason: "assessment unavailable (SSL Labs returned no result)" },
    );
  }
  if (reconRunResult) {
    const r = reconRunResult.recon;
    tests.push(
      { group: "recon", name: `DNS records (${r.dnsRecords.length})`, status: "ran", findings: 0, durationMs: r.reconDurationMs },
      { group: "recon", name: `subdomain enumeration (${r.subdomains.length} found)`, status: "ran", findings: 0, durationMs: r.reconDurationMs },
      allowActiveProbes
        ? { group: "recon", name: `port scan (${r.openPorts.length} open)`, status: "ran", findings: reconRunResult.vulns.length, durationMs: r.reconDurationMs }
        : { group: "recon", name: "port scan", status: "skipped", findings: 0, durationMs: 0, reason: NOT_VERIFIED },
    );
  } else {
    tests.push({ group: "recon", name: "reconnaissance (DNS, subdomains, ports)", status: "failed", findings: 0, durationMs: sideMs, reason: "recon did not return results" });
  }
  // The scanner's own tests were sent live as they ended; these were added here.
  for (const t of tests.slice(scanResult.tests?.length ?? 0)) live.add(t);
  await live.finish();
  for (const t of tests) {
    const line = formatTestLine(t);
    if (t.status === "failed") log.warn({ test: t }, line);
    else log.info({ test: t }, line);
  }
  log.info({ tests: tests.length }, formatTestSummary(tests));
  return tests;
}

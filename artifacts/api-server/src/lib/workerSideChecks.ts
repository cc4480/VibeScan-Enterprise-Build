import type { ScanResult } from "./scanner";
import type { Log, SslLabsResult, ReconRunResult, LiveProgress } from "./workerTypes";
import { and } from "drizzle-orm";
import { type ScanVulnerability } from "./scanner";
import { formatTestLine, formatTestSummary, NOT_VERIFIED, type TestRecord } from "./testLedger";
import { randomUUID } from "node:crypto";

/** Folds the SSL Labs grade into the scan: overrides the basic TLS grade and adds a weak-TLS finding. */
export function mergeSslLabs(scanResult: ScanResult, sslLabsResult: SslLabsResult, log: Log): void {
  if (sslLabsResult) {
    log.info({ grade: sslLabsResult.grade, issues: sslLabsResult.issues.length }, "SSL Labs assessment complete");
    // Override the basic TLS grade with the real SSL Labs grade
    scanResult.tlsGrade = sslLabsResult.grade;

    // Add SSL Labs findings as vulnerabilities
    if (sslLabsResult.grade && /^[C-F]$/.test(sslLabsResult.grade)) {
      scanResult.vulnerabilities.push({
        id: randomUUID(),
        name: `Weak TLS Configuration (SSL Labs Grade: ${sslLabsResult.grade})`,
        severity: sslLabsResult.grade === "F" ? "critical" : sslLabsResult.grade === "D" ? "high" : "medium",
        category: "Transport Security",
        description: `SSL Labs graded your TLS configuration as ${sslLabsResult.grade}. This indicates weak cipher suites, outdated protocol support, or certificate issues that could expose users to downgrade attacks.`,
        evidence: sslLabsResult.issues.join("; ") || null,
        solution: "Use a modern TLS configuration: TLS 1.2 minimum, TLS 1.3 preferred, disable RC4/3DES/CBC-mode cipher suites, and enable HSTS. Use Mozilla's SSL Configuration Generator for server-specific settings.",
        cweId: "CWE-326",
        cvssScore: sslLabsResult.grade === "F" ? 9.1 : sslLabsResult.grade === "D" ? 7.5 : 5.3,
      } satisfies ScanVulnerability);
    }
  } else {
    log.warn("SSL Labs assessment not available — using basic TLS detection");
  }
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
 * Everything the scan was meant to run — the scanner's own ledger plus SSL Labs and
 * reconnaissance, which run beside it — each with its outcome, sent live and logged
 * one line per test.
 */
export async function recordSideTests(input: {
  scanResult: ScanResult;
  sslLabsResult: SslLabsResult;
  reconRunResult: ReconRunResult;
  allowActiveProbes: boolean;
  parallelStartedAt: number;
  live: LiveProgress;
  log: Log;
}): Promise<TestRecord[]> {
  const { scanResult, sslLabsResult, reconRunResult, allowActiveProbes, parallelStartedAt, live, log } = input;
  const tests: TestRecord[] = [...(scanResult.tests ?? [])];
  const sideMs = Date.now() - parallelStartedAt;
  tests.push(
    sslLabsResult
      ? { group: "transport", name: `SSL Labs TLS grade (${sslLabsResult.grade ?? "no grade"})`, status: "ran", findings: sslLabsResult.grade && /^[C-F]$/.test(sslLabsResult.grade) ? 1 : 0, durationMs: sideMs }
      : { group: "transport", name: "SSL Labs TLS grade", status: "failed", findings: 0, durationMs: sideMs, reason: "assessment unavailable (basic TLS detection used)" },
  );
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

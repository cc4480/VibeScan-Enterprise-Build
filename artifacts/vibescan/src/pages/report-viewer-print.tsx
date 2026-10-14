/** The printable report and its PDF download. */

import type { Vulnerability } from "@workspace/api-client-react";
import { isRepoOnlyReport } from "@/lib/repo-only-report";
import { APP_ORIGIN } from "@/lib/origin";
import { NO_FINDINGS_WITH_NOTES, SCAN_NOTES_BLURB, SCAN_NOTES_TITLE } from "@/lib/scan-notes";
import { PrintCoverage, PrintSourceCode, type CoverageTest } from "./shared-report-components";
import { getCategoryMeta, type ComplianceData } from "./report-viewer-data";
import { PrintGradeRing, PrintVulnCard } from "./report-viewer-print-parts";
import { PrintWithheld, type Interception } from "./report-viewer-provenance";
export { PrintGradeRing, PrintVulnCard } from "./report-viewer-print-parts";

export { DownloadPDFButton } from "./report-viewer-pdf";

// ─── Full printable report (screen: hidden; print: visible) ───────────────────

export function PrintableReport({
  targetUrl, scannedAt, summary, confirmedVulns, unverifiedVulns, scanNotes,
  technologies, server, tlsGrade, aiAnalysis, compliance, categoryCounts, pagesScanned, tests,
  withheld, interception,
}: {
  targetUrl: string;
  scannedAt: string | Date;
  summary: { grade: string; riskScore: number; executiveSummary: string; critical: number; high: number; medium: number; low: number; info: number; totalVulnerabilities: number };
  confirmedVulns: Vulnerability[];
  unverifiedVulns: Vulnerability[];
  /** The scan's notes about itself, which are not findings (see lib/scan-notes.ts). */
  scanNotes?: Vulnerability[];
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: { overallRisk: string; topPriorities: string[]; quickWins: string[]; complianceNotes?: string | null } | null;
  compliance?: ComplianceData | null;
  categoryCounts: Record<string, number>;
  pagesScanned?: string[];
  tests?: CoverageTest[] | null;
  withheld?: unknown;
  interception?: Interception | null;
}) {
  const dateStr = new Date(scannedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const sortedCategories = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]);

  return (
    <div className="text-gray-900 bg-white font-sans text-sm leading-relaxed max-w-4xl mx-auto py-4">
      {/* Cover */}
      <div className="mb-8 pb-6 border-b-2 border-gray-300">
        <div className="flex items-start gap-6 mb-4">
          <PrintGradeRing grade={summary.grade} score={summary.riskScore} />
          <div className="flex-1 pt-2">
            <h1 className="text-2xl font-bold text-gray-900 mb-1">Security Report</h1>
            <p className="text-gray-500 text-sm mb-3">{targetUrl}</p>
            <div className="flex flex-wrap gap-6 text-sm text-gray-600">
              <span><strong>Total Findings:</strong> {summary.totalVulnerabilities}</span>
              <span><strong>Scanned:</strong> {dateStr}</span>
              {tlsGrade && <span><strong>TLS Grade:</strong> {tlsGrade}</span>}
            </div>
          </div>
        </div>
      </div>

      {/* Severity summary */}
      <div className="mb-6 flex gap-3 flex-wrap">
        {summary.critical > 0 && <span className="px-3 py-1 bg-red-100 text-red-800 rounded text-sm font-medium border border-red-200">🔴 Critical: {summary.critical}</span>}
        {summary.high > 0 && <span className="px-3 py-1 bg-orange-100 text-orange-800 rounded text-sm font-medium border border-orange-200">🟠 High: {summary.high}</span>}
        {summary.medium > 0 && <span className="px-3 py-1 bg-yellow-100 text-yellow-800 rounded text-sm font-medium border border-yellow-200">🟡 Medium: {summary.medium}</span>}
        {summary.low > 0 && <span className="px-3 py-1 bg-blue-100 text-blue-800 rounded text-sm font-medium border border-blue-200">🔵 Low: {summary.low}</span>}
        {summary.info > 0 && <span className="px-3 py-1 bg-gray-100 text-gray-700 rounded text-sm font-medium border border-gray-200">⚪ Info: {summary.info}</span>}
      </div>

      {/* Category breakdown */}
      {sortedCategories.length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-bold mb-3 text-gray-900">📋 Finding Categories</h2>
          <div className="grid grid-cols-2 gap-2">
            {sortedCategories.map(([cat, count]) => (
              <div key={cat} className="flex items-center justify-between px-3 py-2 bg-gray-50 border border-gray-200 rounded">
                <span className="text-sm text-gray-700">{getCategoryMeta(cat).label}</span>
                <span className="text-xs font-bold text-gray-500 bg-gray-200 px-2 py-0.5 rounded-full">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Executive Summary */}
      <div className="mb-8">
        <h2 className="text-lg font-bold mb-2 text-gray-900">Executive Summary</h2>
        <p className="text-gray-700 leading-relaxed">{summary.executiveSummary}</p>
      </div>

      {/* What was tested, and what was not — a PDF is what gets forwarded, so it carries this. */}
      <PrintSourceCode tests={tests} vulnerabilities={[...confirmedVulns, ...unverifiedVulns]} />
      <PrintCoverage tests={tests} />
      <PrintWithheld withheld={withheld} interception={interception} />

      {/* Pages Scanned */}
      {isRepoOnlyReport(targetUrl, tests) ? null : ((): React.ReactNode => {
        const allPages = [targetUrl, ...Array.from(new Set(pagesScanned ?? []))];
        return (
          <div className="mb-8 pt-6 border-t-2 border-gray-200">
            <h2 className="text-lg font-bold mb-3 text-gray-900">🔍 Pages Scanned ({allPages.length})</h2>
            <div className="border border-gray-200 rounded-lg overflow-hidden">
              {allPages.map((url, i) => (
                <div
                  key={i}
                  className={`px-3 py-2 font-mono text-xs text-gray-700 break-all ${i % 2 === 0 ? "bg-white" : "bg-gray-50"} border-b border-gray-100 last:border-b-0`}
                >
                  {url}
                  {i === 0 && <span className="ml-2 text-gray-400 font-sans not-italic">(root)</span>}
                </div>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Confirmed Findings */}
      {confirmedVulns.length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-bold mb-4 text-green-700">✅ Confirmed Findings ({confirmedVulns.length})</h2>
          <div className="space-y-4">
            {confirmedVulns.map((v, i) => <PrintVulnCard key={v.id} vuln={v} index={i + 1} />)}
          </div>
        </div>
      )}

      {/* Needs Verification */}
      {unverifiedVulns.length > 0 && (
        <div className="mb-8 mt-8 pt-6 border-t-2 border-gray-200">
          <h2 className="text-lg font-bold mb-2 text-amber-700">⚠️ Needs Verification ({unverifiedVulns.length})</h2>
          <p className="text-sm text-gray-500 mb-4">These findings were detected using heuristics. Verify manually before prioritising remediation.</p>
          <div className="space-y-4">
            {unverifiedVulns.map((v, i) => <PrintVulnCard key={v.id} vuln={v} index={i + 1} />)}
          </div>
        </div>
      )}

      {/* No findings, but the scan left notes about itself: not a clean result. */}
      {confirmedVulns.length === 0 && unverifiedVulns.length === 0 && (scanNotes?.length ?? 0) > 0 && (
        <div className="mb-8 mt-8 pt-6 border-t-2 border-gray-200">
          <h2 className="text-lg font-bold mb-2 text-gray-700">{NO_FINDINGS_WITH_NOTES.title}</h2>
          <p className="text-sm text-gray-500">{NO_FINDINGS_WITH_NOTES.body}</p>
        </div>
      )}

      {/* About this scan: the scan's own notes, kept apart from the findings. */}
      {scanNotes && scanNotes.length > 0 && (
        <div className="mb-8 mt-8 pt-6 border-t-2 border-gray-200">
          <h2 className="text-lg font-bold mb-2 text-gray-700">ℹ️ {SCAN_NOTES_TITLE} ({scanNotes.length})</h2>
          <p className="text-sm text-gray-500 mb-4">{SCAN_NOTES_BLURB}</p>
          <div className="space-y-4">
            {scanNotes.map((v, i) => <PrintVulnCard key={v.id} vuln={v} index={i + 1} />)}
          </div>
        </div>
      )}

      {/* AI Analysis */}
      {aiAnalysis && (
        <div className="mb-8 mt-8 pt-6 border-t-2 border-gray-200">
          <h2 className="text-lg font-bold mb-4 text-gray-900">🤖 AI Analysis</h2>
          <div className="space-y-4">
            <div>
              <h3 className="font-semibold text-gray-800 mb-1">Overall Risk</h3>
              <p className="text-gray-700">{aiAnalysis.overallRisk}</p>
            </div>
            {(aiAnalysis.topPriorities?.length ?? 0) > 0 && (
              <div>
                <h3 className="font-semibold text-gray-800 mb-2">Top Priorities</h3>
                <ol className="list-decimal list-inside space-y-1">
                  {aiAnalysis.topPriorities.map((p, i) => <li key={i} className="text-gray-700">{p}</li>)}
                </ol>
              </div>
            )}
            {(aiAnalysis.quickWins?.length ?? 0) > 0 && (
              <div>
                <h3 className="font-semibold text-gray-800 mb-2">Quick Wins</h3>
                <ul className="space-y-1">
                  {aiAnalysis.quickWins.map((w, i) => <li key={i} className="text-gray-700">✓ {w}</li>)}
                </ul>
              </div>
            )}
            {aiAnalysis.complianceNotes && (
              <div>
                <h3 className="font-semibold text-gray-800 mb-1">Compliance Notes</h3>
                <p className="text-gray-700">{aiAnalysis.complianceNotes}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Compliance Mapping */}
      {compliance && compliance.frameworks.length > 0 && (
        <div className="mb-8 mt-8 pt-6 border-t-2 border-gray-200">
          <h2 className="text-lg font-bold mb-1 text-gray-900">Compliance Mapping</h2>
          <p className="text-xs text-gray-500 mb-4">
            Which findings are evidence for a recognised framework control — not a compliance verdict.
          </p>
          <div className="space-y-4">
            {compliance.frameworks.map((fw) => (
              <div key={fw.framework.id}>
                <h3 className="font-semibold text-gray-800">
                  {fw.framework.name} <span className="text-xs font-normal text-gray-500">{fw.framework.version}</span>
                </h3>
                <ul className="mt-1 mb-1 space-y-0.5">
                  {fw.controls.map((c) => (
                    <li key={c.control} className="text-gray-700 text-sm">
                      <span className="font-mono text-xs">{c.control}</span> {c.title}{" "}
                      <span className="text-gray-500">({c.findings} finding{c.findings === 1 ? "" : "s"})</span>
                    </li>
                  ))}
                </ul>
                <p className="text-xs text-gray-400">{fw.framework.note}</p>
              </div>
            ))}
          </div>
          <p className="text-xs text-gray-400 mt-4 pt-3 border-t border-gray-100">{compliance.disclaimer}</p>
        </div>
      )}

      {/* Tech Profile */}
      {!isRepoOnlyReport(targetUrl, tests) && (
      <div className="mb-6 mt-8 pt-6 border-t-2 border-gray-200">
        <h2 className="text-lg font-bold mb-3 text-gray-900">🖥️ Tech Profile</h2>
        {tlsGrade && <p className="text-gray-700 mb-1"><strong>TLS Grade:</strong> {tlsGrade}</p>}
        {server && <p className="text-gray-700 mb-1"><strong>Server:</strong> {server}</p>}
        {technologies.length > 0 && <p className="text-gray-700"><strong>Technologies:</strong> {technologies.join(", ")}</p>}
      </div>
      )}

      {/* Footer */}
      <div className="pt-4 border-t border-gray-200 text-center text-xs text-gray-400 mt-8">
        Generated by SecScan — {APP_ORIGIN} &nbsp;|&nbsp; {dateStr}
      </div>
    </div>
  );
}

// ─── Download PDF button (jspdf + html2canvas) ───────────────────────────────

export interface PrintableReportData {
  targetUrl: string;
  scannedAt: string | Date;
  summary: {
    grade: string;
    riskScore: number;
    executiveSummary: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    totalVulnerabilities: number;
  };
  confirmedVulns: Vulnerability[];
  unverifiedVulns: Vulnerability[];
  /** The scan's notes about itself, which are not findings (see lib/scan-notes.ts). */
  scanNotes?: Vulnerability[];
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: { overallRisk: string; topPriorities: string[]; quickWins: string[]; complianceNotes?: string | null; agentFixPrompt?: string | null; source?: "ai" | "template" } | null;
  compliance?: ComplianceData | null;
  categoryCounts: Record<string, number>;
  pagesScanned?: string[];
  tests?: CoverageTest[] | null;
  withheld?: unknown;
  interception?: Interception | null;
}
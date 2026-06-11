import { useState, useRef } from "react";
import type React from "react";
import { Loader2, Download } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Vulnerability } from "@workspace/api-client-react";
import { getCategoryMeta } from "./report-viewer-utils";


// ─── Severity emoji for print / markdown ─────────────────────────────────────

export const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪",
};

// ─── Print-friendly grade ring ────────────────────────────────────────────────

export function PrintGradeRing({ grade, score }: { grade: string; score: number }) {
  const colorMap: Record<string, string> = {
    A: "#059669", B: "#16a34a", C: "#ca8a04", D: "#ea580c", F: "#dc2626",
  };
  const color = colorMap[grade] ?? "#6b7280";
  const r = 52;
  const circumference = 2 * Math.PI * r;
  const dash = circumference * (score / 100);

  return (
    <div style={{ position: "relative", width: 120, height: 120, flexShrink: 0 }}>
      <svg width="120" height="120" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="#e5e7eb" strokeWidth="6" />
        <circle
          cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${dash} ${circumference - dash}`}
          strokeLinecap="round"
        />
      </svg>
      <div style={{
        position: "absolute", inset: 0, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
      }}>
        <span style={{ fontSize: 36, fontWeight: 900, lineHeight: 1, color }}>{grade}</span>
        <span style={{ fontSize: 10, color: "#6b7280", marginTop: 2 }}>Risk: {score}</span>
      </div>
    </div>
  );
}

// ─── Print-friendly vuln card (used inside PrintableReport) ───────────────────

export function PrintVulnCard({ vuln, index }: { vuln: Vulnerability; index: number }) {
  const borderColors: Record<string, string> = {
    critical: "border-red-300 bg-red-50",
    high:     "border-orange-300 bg-orange-50",
    medium:   "border-yellow-300 bg-yellow-50",
    low:      "border-blue-300 bg-blue-50",
    info:     "border-gray-300 bg-gray-50",
  };
  const headerColors: Record<string, string> = {
    critical: "text-red-800",
    high:     "text-orange-800",
    medium:   "text-yellow-800",
    low:      "text-blue-800",
    info:     "text-gray-700",
  };
  const emoji = SEVERITY_EMOJI[vuln.severity] ?? "•";
  const border = borderColors[vuln.severity] ?? "border-gray-300 bg-gray-50";
  const hdr = headerColors[vuln.severity] ?? "text-gray-700";

  return (
    <div className={`border rounded-lg overflow-hidden ${border}`} style={{ pageBreakInside: "avoid" }}>
      <div className={`px-4 py-2.5 flex items-center gap-3 border-b border-current/20 ${border}`}>
        <span className={`font-bold uppercase text-xs tracking-wider ${hdr}`}>{emoji} {vuln.severity}</span>
        <span className="font-semibold text-gray-900 text-sm">{index}. {vuln.name}</span>
        <span className="ml-auto text-xs text-gray-500 shrink-0">{vuln.category}</span>
      </div>
      <div className="px-4 py-3 bg-white space-y-3">
        <div>
          <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">Description</p>
          <p className="text-gray-800 text-sm leading-relaxed">{vuln.description}</p>
        </div>
        {vuln.evidence && (
          <div>
            <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">Evidence</p>
            <pre className="text-xs bg-gray-50 border border-gray-200 rounded p-2 whitespace-pre-wrap text-gray-600 font-mono">{vuln.evidence}</pre>
          </div>
        )}
        <div>
          <p className="text-xs font-bold uppercase text-gray-400 mb-1 tracking-wider">How to Fix</p>
          <div className="bg-emerald-50 border border-emerald-200 rounded p-3 text-sm text-gray-800 whitespace-pre-wrap">{vuln.solution}</div>
        </div>
        {(vuln.cweId || vuln.cvssScore != null || vuln.wstgId) && (
          <div className="flex gap-2 flex-wrap">
            {vuln.cweId && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">{vuln.cweId}</span>}
            {vuln.cvssScore != null && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">CVSS {vuln.cvssScore.toFixed(1)}</span>}
            {vuln.wstgId && <span className="px-2 py-0.5 bg-gray-100 border border-gray-200 rounded text-xs text-gray-600">{vuln.wstgId}</span>}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Full printable report (screen: hidden; print: visible) ───────────────────

export function PrintableReport({
  targetUrl, scannedAt, summary, confirmedVulns, unverifiedVulns,
  technologies, server, tlsGrade, aiAnalysis, categoryCounts, pagesScanned,
}: {
  targetUrl: string;
  scannedAt: string | Date;
  summary: { grade: string; riskScore: number; executiveSummary: string; critical: number; high: number; medium: number; low: number; info: number; totalVulnerabilities: number };
  confirmedVulns: Vulnerability[];
  unverifiedVulns: Vulnerability[];
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: { overallRisk: string; topPriorities: string[]; quickWins: string[]; complianceNotes?: string | null } | null;
  categoryCounts: Record<string, number>;
  pagesScanned?: string[];
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

      {/* Pages Scanned */}
      {((): React.ReactNode => {
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
          <h2 className="text-lg font-bold mb-4 text-emerald-700">✅ Confirmed Findings ({confirmedVulns.length})</h2>
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

      {/* Tech Profile */}
      <div className="mb-6 mt-8 pt-6 border-t-2 border-gray-200">
        <h2 className="text-lg font-bold mb-3 text-gray-900">🖥️ Tech Profile</h2>
        {tlsGrade && <p className="text-gray-700 mb-1"><strong>TLS Grade:</strong> {tlsGrade}</p>}
        {server && <p className="text-gray-700 mb-1"><strong>Server:</strong> {server}</p>}
        {technologies.length > 0 && <p className="text-gray-700"><strong>Technologies:</strong> {technologies.join(", ")}</p>}
      </div>

      {/* Footer */}
      <div className="pt-4 border-t border-gray-200 text-center text-xs text-gray-400 mt-8">
        Generated by VibeScan — https://vibescan.app &nbsp;|&nbsp; {dateStr}
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
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: { overallRisk: string; topPriorities: string[]; quickWins: string[]; complianceNotes?: string | null } | null;
  categoryCounts: Record<string, number>;
  pagesScanned?: string[];
}

export function DownloadPDFButton({ data }: { data: PrintableReportData }) {
  const [generating, setGenerating] = useState(false);
  const [showOffscreen, setShowOffscreen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const handleDownload = async () => {
    if (generating) return;
    setGenerating(true);
    setShowOffscreen(true);
    // Wait for React to render the off-screen PrintableReport
    await new Promise<void>((r) => setTimeout(r, 300));

    try {
      const container = containerRef.current;
      if (!container) return;

      const [{ default: html2canvas }, { jsPDF }] = await Promise.all([
        import("html2canvas"),
        import("jspdf"),
      ]);

      const canvas = await html2canvas(container, {
        scale: 1.5,
        useCORS: true,
        logging: false,
        backgroundColor: "#ffffff",
        windowWidth: container.scrollWidth,
        windowHeight: container.scrollHeight,
      });

      const imgData = canvas.toDataURL("image/png");
      const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
      const pageW = pdf.internal.pageSize.getWidth();
      const pageH = pdf.internal.pageSize.getHeight();
      const imgHeightMm = (canvas.height / canvas.width) * pageW;

      let heightLeft = imgHeightMm;
      let yOffset = 0;

      pdf.addImage(imgData, "PNG", 0, yOffset, pageW, imgHeightMm);
      heightLeft -= pageH;

      while (heightLeft > 0) {
        yOffset -= pageH;
        pdf.addPage();
        pdf.addImage(imgData, "PNG", 0, yOffset, pageW, imgHeightMm);
        heightLeft -= pageH;
      }

      let filename = "vibescan-report.pdf";
      try {
        const host = new URL(data.targetUrl).hostname.replace(/^www\./, "");
        filename = `vibescan-${host}.pdf`;
      } catch {
        // keep default
      }
      pdf.save(filename);
    } finally {
      setShowOffscreen(false);
      setGenerating(false);
    }
  };

  return (
    <>
      {/* Off-screen container for PDF capture — visible to html2canvas but off-viewport */}
      {showOffscreen && (
        <div
          ref={containerRef}
          style={{
            position: "fixed",
            left: "-9999px",
            top: 0,
            width: "794px",
            backgroundColor: "#ffffff",
            zIndex: -1,
            pointerEvents: "none",
          }}
        >
          <PrintableReport {...data} />
        </div>
      )}

      <button
        onClick={() => void handleDownload()}
        disabled={generating}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-secondary border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors disabled:opacity-60"
      >
        {generating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
        {generating ? "Generating…" : "Download PDF"}
      </button>
    </>
  );
}

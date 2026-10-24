import type { SeverityCounts } from "./shared-report-components";
import type { ReactNode } from "react";
import type { PrintableReportData } from "./report-viewer-print";
import type { ReportCopyData } from "./report-viewer-copy";
import type { ReportResponse, ReportPayload } from "./report-viewer-types";
import { Vulnerability } from "@workspace/api-client-react";
import { Link } from "wouter";
import { Shield, Globe, Plus, HelpCircle, Bell, Search, CheckCircle2 } from "lucide-react";
import { GradeRing, GRADE_HEX } from "@/components/grade-ring";
import { scannedPagesLabel } from "@/lib/scanned-pages-label";
import { SeverityLegend } from "./shared-report-components";
import { SummaryNewFindings } from "./report-viewer-categories";
import { DownloadPDFButton } from "./report-viewer-print";
import { CopyReportButton } from "./report-viewer-copy";
import { ShareButton } from "./report-viewer-share";
import { EvidencePackButton } from "./report-viewer-evidence";
import { useReportBrand, useViewOnly } from "@/lib/use-view-only";

/** The cover: grade ring, target, executive summary and the severity legend. */
export function ReportCover({ report, summary, pagesScanned, severityCounts, categoryCounts, allUnverifiedVulns, fixedNotice, repoOnly = false }: {
  report: ReportResponse;
  summary: NonNullable<ReportPayload["summary"]>;
  pagesScanned: ReportPayload["pagesScanned"];
  severityCounts: SeverityCounts;
  categoryCounts: Record<string, number>;
  allUnverifiedVulns: Vulnerability[];
  /** Set when findings have been verified fixed since the scan; says what did and did not change. */
  fixedNotice?: string | null;
  /** A repository scanned alone: the "also detected" labels describe a website's checks, so they are left out. */
  repoOnly?: boolean;
}) {
  // Information findings carry no weight in the grade, so only the others are "in" it.
  const weighed = allUnverifiedVulns.filter((v) => v.severity !== "info");
  // The same rule the ring uses: a grade outside A to F means no real grade was
  // given, which is what a bot-protection interception produces ("N/A").
  const pagesLabel = scannedPagesLabel(pagesScanned, !(summary.grade in GRADE_HEX));
  return (
    <div className="glass-panel p-8 md:p-12 rounded-3xl mb-12 relative overflow-hidden flex flex-col md:flex-row items-center gap-12">
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px] pointer-events-none" />

      <div className="z-10 shrink-0">
        <GradeRing grade={summary.grade} score={summary.riskScore} size="lg" />
      </div>

      <div className="flex-1 text-center md:text-left z-10">
        <div className="flex flex-wrap items-center gap-2 mb-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary border border-white/5 text-xs font-medium text-muted-foreground">
            <Globe className="w-3.5 h-3.5" /> {report.targetUrl}
          </div>
          {pagesLabel && (
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-sky-500/10 border border-sky-500/20 text-xs font-medium text-sky-400/80">
              <Search className="w-3 h-3" />
              {pagesLabel}
            </div>
          )}
        </div>
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4">Security Report</h1>
        <p className="text-lg text-muted-foreground/80 leading-relaxed max-w-2xl">
          {summary.executiveSummary}
        </p>
        <div className="mt-5">
          <SeverityLegend counts={severityCounts} />
        </div>
        {fixedNotice && (
          <div className="mt-3 inline-flex items-start gap-2 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/25 text-xs text-green-300 text-left">
            <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            {fixedNotice}
          </div>
        )}
        {!repoOnly && <SummaryNewFindings categories={categoryCounts} />}
        {weighed.length > 0 && (
          <div className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/25 text-xs text-amber-300">
            <HelpCircle className="w-3.5 h-3.5 shrink-0" />
            Grade includes {weighed.length} heuristic finding{weighed.length !== 1 ? "s" : ""} — see "Needs Verification" below before acting
          </div>
        )}
      </div>
    </div>
  );
}

/** Copy, PDF, evidence pack and share for a report. */
export function ReportActionButtons({ copyData, pdfData, reportId }: { copyData: ReportCopyData; pdfData: PrintableReportData; reportId: string }) {
  // A teammate reads the report; sharing it is the owner's to do.
  const { viewOnly } = useViewOnly(reportId);
  const brand = useReportBrand(reportId);
  return (
    <>
      <CopyReportButton data={copyData} />
      <DownloadPDFButton data={pdfData} brand={brand} />
      <EvidencePackButton reportId={reportId} />
      {!viewOnly && <ShareButton reportId={reportId} />}
    </>
  );
}

export function MonitorCta() {
  return (
    <div className="glass-panel rounded-2xl p-6 border border-indigo-500/25 bg-indigo-500/5 flex flex-col sm:flex-row items-center gap-6">
      <div className="w-12 h-12 rounded-xl bg-indigo-500/15 border border-indigo-500/25 flex items-center justify-center shrink-0">
        <Bell className="w-6 h-6 text-indigo-400" />
      </div>
      <div className="flex-1 text-center sm:text-left">
        <h3 className="font-bold text-lg mb-1">Keep watching this URL</h3>
        <p className="text-sm text-muted-foreground">
          Hourly checks, risk-adaptive rescans and CVE alerts when new vulnerabilities match your tech stack. <span className="text-indigo-400 font-semibold">Included in every plan — from $19/month</span>
        </p>
      </div>
      <Link
        href="/monitor"
        className="shrink-0 px-6 py-3 bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-xl font-bold hover:bg-indigo-500/30 transition-all whitespace-nowrap flex items-center gap-2"
      >
        <Bell className="w-4 h-4" /> Start Monitoring
      </Link>
    </div>
  );
}

/** "Scan another website", with the report actions passed in as children. */
export function ScanAnotherCta({ children }: { children: ReactNode }) {
  return (
    <>
      <div className="glass-panel rounded-3xl p-8 md:p-12 text-center border border-primary/20 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
        <Shield className="w-12 h-12 text-primary mx-auto mb-4" />
        <h2 className="text-2xl md:text-3xl font-bold mb-3">Scan another website</h2>
        <p className="text-muted-foreground mb-8 max-w-md mx-auto">
          Check a different URL, a staging environment, or a client's site — most scans finish in under a minute.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] hover:-translate-y-1 transition-all duration-300"
          >
            <Plus className="w-5 h-5" /> New Scan
          </Link>
          {children}
      </div>
      </div>
    </>
  );
}

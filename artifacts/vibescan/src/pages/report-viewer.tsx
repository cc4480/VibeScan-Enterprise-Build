import type { PrintableReportData } from "./report-viewer-print";
import { useReportDismissals, useVulnGroups } from "./report-viewer-hooks";
import { ReportLoading, ReportLoadFailure, UndoToast } from "./report-viewer-states";
import { isRepoOnlyReport } from "@/lib/repo-only-report";
import { isViewOnly } from "@/lib/team";
import { ReportCover, ReportActionButtons, MonitorCta, ScanAnotherCta } from "./report-viewer-cover";
import { VerifyBanner } from "./report-viewer-verify";
import { FindingsHeading, SeverityBadges, SortViewToggles, CategoryFilterPills, AccuracyBar } from "./report-viewer-filters";
import { ConfirmedFindings, FixedFindings, UnverifiedFindings, EmptyFindings, ScanNotes } from "./report-viewer-findings";
import { CategoryBreakdownCard, AiAnalysisCard, TechProfileCard } from "./report-viewer-sidebar";
import { useGetReport, getGetReportQueryKey, useGetCurrentAuthUser } from "@workspace/api-client-react";
import { useRoute, Link } from "wouter";
import { ArrowLeft } from "lucide-react";
import { ReportChangesCard } from "@/components/report-changes-card";
import type { ScanChanges } from "@/lib/report-changes";
import { useMemo, useState } from "react";
import { useVerifications } from "@/lib/use-verifications";
import { fixedFindingIds, fixedNotice, latestFixDate, subtractFixed } from "@/lib/fixed-findings";
import { useSeo } from "@/lib/seo";
import { ComplianceCard, CoverageCard, SourceCodeCard, type CoverageTest } from "./shared-report-components";
import { ReportTestsContext, WithheldCard, type Interception } from "./report-viewer-provenance";
import { type ComplianceData, DismissalsContext } from "./report-viewer-data";
import { OwaspBreakdown } from "./report-viewer-charts";
import { ReconCard } from "./report-viewer-recon";
import { PagesScannedCard, SoftwareInventoryCard } from "./report-viewer-inventory";
import { AgentFixPromptCard } from "./report-viewer-agents";
import { PrintableReport } from "./report-viewer-print";
import { type ReportCopyData } from "./report-viewer-copy";

export type { PrintableReportData } from "./report-viewer-print";

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ReportViewer() {
  useSeo({ title: "Security Report — SecScan.us", noindex: true });
  const [, params] = useRoute("/report/:id");
  const reportId = params?.id || "";
  // Read only to NAME the signed-in account in the wrong-account error below.
  // Called here because a hook cannot run after this component's early returns.
  const { data: currentUser } = useGetCurrentAuthUser();
  const { data: report, isLoading, error } = useGetReport(reportId, {
    query: {
      queryKey: getGetReportQueryKey(reportId),
      enabled: !!params?.id,
    },
  });

  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"severity" | "category">("severity");
  const [viewMode, setViewMode] = useState<"grouped" | "flat">("grouped");

  const vulnerabilities = report?.data?.vulnerabilities ?? [];
  const summary = report?.data?.summary;

  const {
    dismissedFps, vulnFpMap, optimisticDismissKeys, undoToast, setUndoToast, undoToastTimerRef, dismissFinding, undismissFinding,
  } = useReportDismissals(report?.targetUrl, vulnerabilities);

  // Re-check results: findings verified fixed leave the open lists (see lib/fixed-findings.ts).
  const verifications = useVerifications(reportId).data?.verifications;
  const fixedIds = useMemo(() => fixedFindingIds(verifications), [verifications]);

  // All hooks must come before any early returns
  const {
    findings, scanNotes, fixedVulns, categoryCounts, sortedCategories, visibleVulns, dismissedCount, filteredVulns, confirmedVulns,
    unverifiedVulns, groupedConfirmedVulns, groupedUnverifiedVulns, allConfirmedVulns, allUnverifiedVulns,
    confirmedSeverityCounts, unverifiedSeverityCounts,
  } = useVulnGroups({ vulnerabilities, sortBy, activeCategory, dismissedFps, vulnFpMap, optimisticDismissKeys, fixedIds });

  if (isLoading) return <ReportLoading />;
  if (error || !report || !summary) {
    return <ReportLoadFailure error={error} reportId={reportId} signedInAs={currentUser?.user?.email} />;
  }

  const { data: { technologies, server, tlsGrade, aiAnalysis, pagesScanned, probedNotFound, recon } } = report;
  // report.data is loosely typed by the client; compliance is frozen in by the
  // worker (see the autoSuppressedCount cast below for the same pattern).
  const compliance = (report.data as { compliance?: ComplianceData | null }).compliance ?? null;
  // What ran and what was skipped; absent on reports from before test records.
  const coverageTests = (report.data as { tests?: CoverageTest[] | null }).tests ?? null;
  // A repository scanned alone has no pages, technologies, certificate or site to monitor: those parts are left out.
  const repoOnly = isRepoOnlyReport(report.targetUrl, coverageTests);
  // Findings the scan produced and did not report, and what answered instead of the app (if anything).
  const withheld = (report.data as { withheld?: unknown }).withheld;
  const interception = (report.data as { interception?: Interception | null }).interception ?? null;
  // What changed since the last scan of this site (computed by the server; absent for a first scan).
  const changes = (report.data as { changes?: ScanChanges | null }).changes ?? null;

  // The scan's own counts, less what has since been verified fixed. The grade is not recomputed.
  const severityCounts = subtractFixed(
    {
      critical: summary.critical,
      high: summary.high,
      medium: summary.medium,
      low: summary.low,
      info: summary.info,
    },
    fixedVulns,
  );
  const fixedCover = fixedNotice(fixedVulns.length, latestFixDate(verifications));

  const copyData: ReportCopyData = {
    targetUrl: report.targetUrl,
    scannedAt: report.scannedAt,
    summary: {
      grade: summary.grade,
      riskScore: summary.riskScore,
      executiveSummary: summary.executiveSummary,
      critical: summary.critical,
      high: summary.high,
      medium: summary.medium,
      low: summary.low,
      info: summary.info,
      totalVulnerabilities: summary.totalVulnerabilities,
    },
    confirmedVulns: allConfirmedVulns,
    unverifiedVulns: allUnverifiedVulns,
    scanNotes,
    technologies: technologies ?? [],
    server: server ?? null,
    tlsGrade: tlsGrade ?? null,
    aiAnalysis: aiAnalysis ?? null,
    compliance,
    tests: coverageTests,
    withheld,
    interception,
  };

  const pdfData: PrintableReportData = {
    targetUrl: report.targetUrl,
    scannedAt: report.scannedAt,
    summary: copyData.summary,
    confirmedVulns: allConfirmedVulns,
    unverifiedVulns: allUnverifiedVulns,
    scanNotes,
    technologies: technologies ?? [],
    server: server ?? null,
    tlsGrade: tlsGrade ?? null,
    aiAnalysis: aiAnalysis ?? null,
    compliance,
    categoryCounts,
    pagesScanned: pagesScanned ?? [],
    tests: coverageTests,
    withheld,
    interception,
  };

  return (
    <DismissalsContext.Provider
      value={{
        dismissedFps,
        vulnFpMap,
        optimisticDismissKeys,
        dismiss: dismissFinding,
        undismiss: undismissFinding,
      }}
    >
    <ReportTestsContext.Provider value={coverageTests}>
    <>
      {/* Print-only view — hidden on screen, shown only when printing */}
      <div className="hidden print:block">
        <PrintableReport
          targetUrl={report.targetUrl}
          scannedAt={report.scannedAt}
          summary={copyData.summary}
          confirmedVulns={allConfirmedVulns}
          unverifiedVulns={allUnverifiedVulns}
          scanNotes={scanNotes}
          technologies={technologies ?? []}
          server={server}
          tlsGrade={tlsGrade}
          aiAnalysis={aiAnalysis}
          compliance={compliance}
          categoryCounts={categoryCounts}
          pagesScanned={pagesScanned ?? []}
          tests={coverageTests}
          withheld={withheld}
          interception={interception}
        />
      </div>

      {/* Interactive screen view — hidden when printing */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-20 print:hidden">
      <div className="mb-8 flex items-center justify-between">
        <Link href="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
        <div className="flex items-center gap-2">
          <ReportActionButtons copyData={copyData} pdfData={pdfData} reportId={reportId} />
        </div>
      </div>
      {isViewOnly(report) && (
        <div role="note" className="mb-6 rounded-lg border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-muted-foreground">
          You are reading this report as a teammate of its owner. It is read-only: you can download the evidence pack, but not share it, re-check fixes or change anything.
        </div>
      )}

      <ReportCover
        report={report}
        summary={summary}
        pagesScanned={repoOnly ? undefined : pagesScanned}
        severityCounts={severityCounts}
        categoryCounts={categoryCounts}
        allUnverifiedVulns={allUnverifiedVulns}
        fixedNotice={fixedCover}
        repoOnly={repoOnly}
      />

      {/* What is waiting on domain verification, directly under the grade: the coverage card
          below is in the sidebar, which on a phone sits under every finding. */}
      <VerifyBanner tests={coverageTests} targetUrl={report.targetUrl} />

      {changes ? <ReportChangesCard changes={changes} /> : null}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        {/* Left Col: Findings */}
        <div className="lg:col-span-2 space-y-8">
          <FindingsHeading report={report} activeCategory={activeCategory} filteredVulns={filteredVulns} visibleVulns={visibleVulns} dismissedCount={dismissedCount} />
          <SeverityBadges confirmedSeverityCounts={confirmedSeverityCounts} unverifiedSeverityCounts={unverifiedSeverityCounts} />
          <SortViewToggles sortBy={sortBy} setSortBy={setSortBy} viewMode={viewMode} setViewMode={setViewMode} />
          {sortedCategories.length > 1 && (
            <CategoryFilterPills sortedCategories={sortedCategories} categoryCounts={categoryCounts} activeCategory={activeCategory} setActiveCategory={setActiveCategory} />
          )}
          {filteredVulns.length > 0 && (
            <AccuracyBar filteredVulns={filteredVulns} confirmedVulns={confirmedVulns} unverifiedVulns={unverifiedVulns} />
          )}
          {confirmedVulns.length > 0 && (
            <ConfirmedFindings confirmedVulns={confirmedVulns} viewMode={viewMode} groupedConfirmedVulns={groupedConfirmedVulns} rootUrl={report.targetUrl} />
          )}
          {unverifiedVulns.length > 0 && (
            <UnverifiedFindings unverifiedVulns={unverifiedVulns} viewMode={viewMode} groupedUnverifiedVulns={groupedUnverifiedVulns} rootUrl={report.targetUrl} />
          )}
          {fixedVulns.length > 0 && <FixedFindings fixedVulns={fixedVulns} rootUrl={report.targetUrl} />}
          <EmptyFindings filteredVulns={filteredVulns} activeCategory={activeCategory} vulnerabilities={findings} scanNotes={scanNotes} />
          {scanNotes.length > 0 && <ScanNotes scanNotes={scanNotes} rootUrl={report.targetUrl} />}
        </div>

        {/* Right Col: OWASP + Category sidebar + AI + Tech */}
        <div className="space-y-8">
          {/* OWASP Top 10 breakdown */}
          {!repoOnly && <OwaspBreakdown vulnerabilities={visibleVulns} tests={coverageTests} />}

          {sortedCategories.length > 0 && (
            <CategoryBreakdownCard
              sortedCategories={sortedCategories}
              categoryCounts={categoryCounts}
              visibleVulns={visibleVulns}
              activeCategory={activeCategory}
              setActiveCategory={setActiveCategory}
              vulnerabilities={findings}
            />
          )}

          {/* AI Analysis */}
          {aiAnalysis && !repoOnly && <AiAnalysisCard aiAnalysis={aiAnalysis} fixedCount={fixedVulns.length} />}

          {/* Compliance mapping — which controls these findings are evidence
              for. Same component the shared report uses; renders nothing when
              no findings map to a framework. */}
          <ComplianceCard compliance={compliance} />

          {/* The repository, when the scan was given one: what was read and what each check found. */}
          <SourceCodeCard tests={coverageTests} vulnerabilities={findings} />

          {/* What the scan tested, and what it skipped — beside the grade's context so a
              clean result is not read as full coverage. */}
          <CoverageCard tests={coverageTests} />

          {/* What the scan found and did not report, and why — nothing dropped out of sight. */}
          <WithheldCard withheld={withheld} interception={interception} />

          {/* Fix with your AI agent */}
          {aiAnalysis?.agentFixPrompt && (
            <AgentFixPromptCard prompt={aiAnalysis.agentFixPrompt} fromTemplate={aiAnalysis.source === "template"} repoOnly={repoOnly} />
          )}

          {/* Software Inventory */}
          {!repoOnly && <SoftwareInventoryCard technologies={technologies ?? []} vulnerabilities={vulnerabilities} />}

          {/* Pages Scanned */}
          {!repoOnly && <PagesScannedCard rootUrl={report.targetUrl} pagesScanned={pagesScanned ?? []} probedNotFound={probedNotFound ?? []} />}

          {/* Reconnaissance */}
          {recon && <ReconCard recon={recon} />}

          {!repoOnly && <TechProfileCard tlsGrade={tlsGrade} server={server} technologies={technologies} />}
        </div>
      </div>

      {!repoOnly && <MonitorCta />}

      <ScanAnotherCta>
        <ReportActionButtons copyData={copyData} pdfData={pdfData} reportId={reportId} />
      </ScanAnotherCta>
      </div>

      <UndoToast undoToast={undoToast} undoToastTimerRef={undoToastTimerRef} setUndoToast={setUndoToast} undismissFinding={undismissFinding} />
    </>
    </ReportTestsContext.Provider>
    </DismissalsContext.Provider>
  );
}

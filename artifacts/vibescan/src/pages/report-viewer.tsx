import {
  useGetReport, getGetReportQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useRoute, Link } from "wouter";
import {
  Shield, ShieldAlert, CheckCircle2, ArrowLeft, Loader2, Globe, Server,
  Lock, Activity, Plus, Filter, X, ArrowUpDown, HelpCircle, Bell, Search,
} from "lucide-react";
import { cn, getSeverityColors, getGradeColor } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import type { Vulnerability } from "@workspace/api-client-react";

import { DismissalsContext, computeVulnFp, vulnUniqueKey, type DismissalEntry } from "./report-viewer-context";
import { getCategoryMeta, SEVERITY_ORDER, VERIFICATION_THRESHOLD, parseTechVersion } from "./report-viewer-utils";
import {
  GradeRing, VulnCard, CategorySection, CategoryPill, SummaryNewFindings,
  AgentFixPromptCard, SoftwareInventoryCard, PagesScannedCard, ReconCard,
} from "./report-viewer-cards";
import { PrintableReport, DownloadPDFButton, type PrintableReportData } from "./report-viewer-print";
import { CopyReportButton, ShareButton, type ReportCopyData } from "./report-viewer-share";

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ReportViewer() {
  const [, params] = useRoute("/report/:id");
  const reportId = params?.id || "";
  const { data: report, isLoading, error } = useGetReport(reportId, {
    query: {
      queryKey: getGetReportQueryKey(reportId),
      enabled: !!params?.id,
    },
  });

  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"severity" | "category">("severity");
  const [viewMode, setViewMode] = useState<"grouped" | "flat">("grouped");

  const [dismissedFps, setDismissedFps] = useState<Set<string>>(new Set());
  const [vulnFpMap, setVulnFpMap] = useState<Map<string, string>>(new Map());
  const [optimisticDismissKeys, setOptimisticDismissKeys] = useState<Set<string>>(new Set());
  const [undoToast, setUndoToast] = useState<{ key: string; vuln: Vulnerability } | null>(null);
  const undoToastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!report?.targetUrl) return;
    fetch(`/api/dismissals?targetUrl=${encodeURIComponent(report.targetUrl)}`)
      .then((r) => (r.ok ? r.json() : []))
      .then((items: DismissalEntry[]) => {
        const fpSet = new Set<string>();
        for (const item of items) fpSet.add(item.fingerprint);
        setDismissedFps(fpSet);
      })
      .catch(() => {});
  }, [report?.targetUrl]);

  const dismissFinding = useCallback(async (vuln: Vulnerability, targetUrl: string) => {
    const vKey = vulnUniqueKey(vuln);

    // Optimistic hide via per-vuln unique key (stays until server fingerprint arrives)
    setOptimisticDismissKeys((prev) => new Set([...prev, vKey]));

    // Show external undo toast (per-card button is gone once the card is hidden)
    if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
    setUndoToast({ key: vKey, vuln });
    undoToastTimerRef.current = setTimeout(() => setUndoToast(null), 5000);

    try {
      const res = await fetch("/api/dismissals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetUrl,
          findingName: vuln.name,
          findingCategory: vuln.category,
          findingEvidence: vuln.evidence ?? undefined,
          reason: "false_positive",
        }),
      });
      if (!res.ok) {
        setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
        if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
        setUndoToast(null);
        return;
      }
      const { fingerprint } = (await res.json()) as { fingerprint: string };
      // Promote from optimistic key to confirmed fingerprint
      setVulnFpMap((prev) => new Map([...prev, [vKey, fingerprint]]));
      setDismissedFps((prev) => new Set([...prev, fingerprint]));
      setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
    } catch {
      setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
      if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
      setUndoToast(null);
    }
  }, []);

  const undismissFinding = useCallback(async (vuln: Vulnerability) => {
    const vKey = vulnUniqueKey(vuln);
    const fp = vulnFpMap.get(vKey);
    const tUrl = report?.targetUrl;
    // Optimistically show the finding again
    setDismissedFps((prev) => { const n = new Set(prev); if (fp) n.delete(fp); return n; });
    setOptimisticDismissKeys((prev) => { const n = new Set(prev); n.delete(vKey); return n; });
    if (fp && tUrl) {
      try {
        const res = await fetch(
          `/api/dismissals/${fp}?targetUrl=${encodeURIComponent(tUrl)}`,
          { method: "DELETE" },
        );
        if (!res.ok) {
          setDismissedFps((prev) => new Set([...prev, fp]));
          return;
        }
        setVulnFpMap((prev) => { const n = new Map(prev); n.delete(vKey); return n; });
      } catch {
        setDismissedFps((prev) => new Set([...prev, fp]));
      }
    }
  }, [vulnFpMap, report?.targetUrl]);

  const vulnerabilities = report?.data?.vulnerabilities ?? [];
  const summary = report?.data?.summary;

  // Pre-compute per-vuln fingerprints using the same SHA-256 algorithm as the server.
  // Runs as a fast async batch whenever the vulnerability list changes.
  useEffect(() => {
    if (!vulnerabilities.length) return;
    let cancelled = false;
    Promise.all(
      vulnerabilities.map((v) =>
        computeVulnFp(v.category, v.name, v.evidence).then(
          (fp) => [vulnUniqueKey(v), fp] as [string, string],
        ),
      ),
    ).then((pairs) => {
      if (!cancelled) setVulnFpMap((prev) => {
        const next = new Map(prev);
        for (const [k, fp] of pairs) next.set(k, fp);
        return next;
      });
    });
    return () => { cancelled = true; };
  }, [vulnerabilities]);

  // All hooks must come before any early returns
  const sortedVulns = useMemo(() => {
    return [...vulnerabilities].sort((a, b) => {
      if (sortBy === "severity") {
        const sd = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
        if (sd !== 0) return sd;
        return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
      }
      const cd = a.category.localeCompare(b.category);
      if (cd !== 0) return cd;
      return (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
    });
  }, [vulnerabilities, sortBy]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of vulnerabilities) {
      counts[v.category] = (counts[v.category] ?? 0) + 1;
    }
    return counts;
  }, [vulnerabilities]);

  const sortedCategories = useMemo(
    () => Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]).map(([c]) => c),
    [categoryCounts],
  );

  const visibleVulns = useMemo(
    () => sortedVulns.filter((v) => {
      const vKey = vulnUniqueKey(v);
      if (optimisticDismissKeys.has(vKey)) return false;
      const fp = vulnFpMap.get(vKey);
      return !fp || !dismissedFps.has(fp);
    }),
    [sortedVulns, dismissedFps, vulnFpMap, optimisticDismissKeys],
  );

  const dismissedCount = sortedVulns.length - visibleVulns.length;

  const filteredVulns = useMemo(
    () => activeCategory ? visibleVulns.filter((v) => v.category === activeCategory) : visibleVulns,
    [visibleVulns, activeCategory],
  );

  // Split into confirmed (confidence ≥ threshold) vs. needs verification
  const confirmedVulns = useMemo(
    () => filteredVulns.filter((v) => (v.confidence ?? 100) >= VERIFICATION_THRESHOLD),
    [filteredVulns],
  );
  const unverifiedVulns = useMemo(
    () => filteredVulns.filter((v) => (v.confidence ?? 100) < VERIFICATION_THRESHOLD),
    [filteredVulns],
  );

  // Grouped confirmed/unverified vulns by category (for grouped view)
  const groupedConfirmedVulns = useMemo(() => {
    const groups: Map<string, Vulnerability[]> = new Map();
    for (const v of confirmedVulns) {
      if (!groups.has(v.category)) groups.set(v.category, []);
      groups.get(v.category)!.push(v);
    }
    return groups;
  }, [confirmedVulns]);

  const groupedUnverifiedVulns = useMemo(() => {
    const groups: Map<string, Vulnerability[]> = new Map();
    for (const v of unverifiedVulns) {
      if (!groups.has(v.category)) groups.set(v.category, []);
      groups.get(v.category)!.push(v);
    }
    return groups;
  }, [unverifiedVulns]);

  // Unfiltered splits — used for PDF/copy so nothing is omitted when a category filter is active
  const allConfirmedVulns = useMemo(
    () => visibleVulns.filter((v) => (v.confidence ?? 100) >= VERIFICATION_THRESHOLD),
    [visibleVulns],
  );
  const allUnverifiedVulns = useMemo(
    () => visibleVulns.filter((v) => (v.confidence ?? 100) < VERIFICATION_THRESHOLD),
    [visibleVulns],
  );

  // Per-severity counts split by confidence — used for the header badges
  const confirmedSeverityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of allConfirmedVulns) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    return counts;
  }, [allConfirmedVulns]);

  const unverifiedSeverityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const v of allUnverifiedVulns) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    return counts;
  }, [allUnverifiedVulns]);

  if (isLoading) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center gap-4">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading report…</p>
      </div>
    );
  }
  if (error || !report || !summary) return <div className="min-h-[80vh] flex items-center justify-center text-red-400">Failed to load report.</div>;

  const { data: { technologies, server, tlsGrade, aiAnalysis, pagesScanned, probedNotFound, recon } } = report;

  const severityCounts = {
    critical: summary.critical,
    high: summary.high,
    medium: summary.medium,
    low: summary.low,
    info: summary.info,
  };

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
    technologies: technologies ?? [],
    server: server ?? null,
    tlsGrade: tlsGrade ?? null,
    aiAnalysis: aiAnalysis ?? null,
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
    <>
      {/* Print-only view — hidden on screen, shown only when printing */}
      <div className="hidden print:block">
        <PrintableReport
          targetUrl={report.targetUrl}
          scannedAt={report.scannedAt}
          summary={copyData.summary}
          confirmedVulns={allConfirmedVulns}
          unverifiedVulns={allUnverifiedVulns}
          technologies={technologies ?? []}
          server={server}
          tlsGrade={tlsGrade}
          aiAnalysis={aiAnalysis}
          categoryCounts={categoryCounts}
          pagesScanned={pagesScanned ?? []}
        />
      </div>

      {/* Interactive screen view — hidden when printing */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-20 print:hidden">
      <div className="mb-8 flex items-center justify-between">
        <Link href="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
        <div className="flex items-center gap-2">
          <CopyReportButton data={copyData} />
          <DownloadPDFButton data={{
            targetUrl: report.targetUrl,
            scannedAt: report.scannedAt,
            summary: copyData.summary,
            confirmedVulns: allConfirmedVulns,
            unverifiedVulns: allUnverifiedVulns,
            technologies: technologies ?? [],
            server: server ?? null,
            tlsGrade: tlsGrade ?? null,
            aiAnalysis: aiAnalysis ?? null,
            categoryCounts,
            pagesScanned: pagesScanned ?? [],
          }} />
          <ShareButton reportId={reportId} />
        </div>
      </div>

      {/* Header / Cover */}
      <div className="glass-panel p-8 md:p-12 rounded-3xl mb-12 relative overflow-hidden flex flex-col md:flex-row items-center gap-12">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px] pointer-events-none" />

        <GradeRing grade={summary.grade} score={summary.riskScore} />

        <div className="flex-1 text-center md:text-left z-10">
          <div className="flex flex-wrap items-center gap-2 mb-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-secondary border border-white/5 text-xs font-medium text-muted-foreground">
              <Globe className="w-3.5 h-3.5" /> {report.targetUrl}
            </div>
            {pagesScanned != null && (
              <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-sky-500/10 border border-sky-500/20 text-xs font-medium text-sky-400/80">
                <Search className="w-3 h-3" />
                Scanned {pagesScanned.length + 1} page{pagesScanned.length + 1 !== 1 ? "s" : ""}
              </div>
            )}
          </div>
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4">Security Report</h1>
          <p className="text-lg text-muted-foreground/80 leading-relaxed max-w-2xl">
            {summary.executiveSummary}
          </p>
          <SummaryNewFindings categories={categoryCounts} />
          {allUnverifiedVulns.length > 0 && (
            <div className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/25 text-xs text-amber-300">
              <HelpCircle className="w-3.5 h-3.5 shrink-0" />
              Grade includes {allUnverifiedVulns.length} heuristic finding{allUnverifiedVulns.length !== 1 ? "s" : ""} — see "Needs Verification" below before acting
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        {/* Left Col: Findings */}
        <div className="lg:col-span-2 space-y-8">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <h2 className="text-2xl font-bold flex items-center gap-3">
              <ShieldAlert className="w-6 h-6 text-primary" />
              Identified Vulnerabilities
              <span className="bg-secondary text-foreground text-sm py-1 px-3 rounded-full ml-2">
                {activeCategory ? `${filteredVulns.length} / ${visibleVulns.length}` : visibleVulns.length}
              </span>
              {dismissedCount > 0 && (
                <span className="text-xs font-normal text-muted-foreground">
                  ({dismissedCount} dismissed as false positive{dismissedCount !== 1 ? "s" : ""})
                </span>
              )}
              {(report?.data as { autoSuppressedCount?: number } | undefined)?.autoSuppressedCount && (
                <span className="text-xs font-normal text-muted-foreground">
                  ({(report.data as { autoSuppressedCount?: number }).autoSuppressedCount} previously dismissed, hidden)
                </span>
              )}
            </h2>
          </div>

          {/* Severity badges — split confirmed vs unverified */}
          <div className="flex flex-wrap gap-3">
            {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
              const confirmed = confirmedSeverityCounts[sev] ?? 0;
              const unverified = unverifiedSeverityCounts[sev] ?? 0;
              if (confirmed + unverified === 0) return null;
              return (
                <div key={sev} className={cn("px-4 py-2 rounded-lg border flex items-center gap-2.5", getSeverityColors(sev))}>
                  <span className="font-bold uppercase text-xs tracking-wider">{sev}</span>
                  <span className="w-6 h-6 rounded bg-black/20 flex items-center justify-center text-sm font-bold">{confirmed + unverified}</span>
                  {unverified > 0 && (
                    <span className="text-xs text-amber-300/80 font-medium border-l border-current/20 pl-2.5">
                      {confirmed} confirmed
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Sort + View mode toggles */}
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <ArrowUpDown className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-xs text-muted-foreground uppercase tracking-wider font-medium">Sort by</span>
              <div className="flex rounded-lg overflow-hidden border border-white/10 ml-1">
                {(["severity", "category"] as const).map((opt) => (
                  <button
                    key={opt}
                    onClick={() => setSortBy(opt)}
                    className={cn(
                      "px-3 py-1.5 text-xs font-medium capitalize transition-colors",
                      sortBy === opt
                        ? "bg-primary/20 text-primary"
                        : "text-muted-foreground hover:text-foreground hover:bg-white/5",
                    )}
                  >
                    {opt}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground uppercase tracking-wider font-medium">View</span>
              <div className="flex rounded-lg overflow-hidden border border-white/10">
                {(["grouped", "flat"] as const).map((opt) => (
                  <button
                    key={opt}
                    onClick={() => setViewMode(opt)}
                    className={cn(
                      "px-3 py-1.5 text-xs font-medium capitalize transition-colors",
                      viewMode === opt
                        ? "bg-primary/20 text-primary"
                        : "text-muted-foreground hover:text-foreground hover:bg-white/5",
                    )}
                  >
                    {opt}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Category filter pills */}
          {sortedCategories.length > 1 && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Filter className="w-3.5 h-3.5" />
                <span className="uppercase tracking-wider font-medium">Filter by category</span>
                {activeCategory && (
                  <button
                    onClick={() => setActiveCategory(null)}
                    className="ml-auto flex items-center gap-1 text-primary hover:text-primary/80 transition-colors font-medium"
                  >
                    <X className="w-3 h-3" /> Clear
                  </button>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                {sortedCategories.map((cat) => (
                  <CategoryPill
                    key={cat}
                    category={cat}
                    count={categoryCounts[cat]}
                    active={activeCategory === cat}
                    onClick={() => setActiveCategory(activeCategory === cat ? null : cat)}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Accuracy bar */}
          {filteredVulns.length > 0 && (
            <div className="flex items-center gap-4 p-3 rounded-xl bg-secondary/40 border border-white/5 text-xs">
              <div className="flex items-center gap-1.5 text-emerald-400 font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{confirmedVulns.length} confirmed</span>
              </div>
              {unverifiedVulns.length > 0 && (
                <>
                  <div className="w-px h-4 bg-white/10" />
                  <div className="flex items-center gap-1.5 text-amber-400 font-medium">
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>{unverifiedVulns.length} need{unverifiedVulns.length === 1 ? "s" : ""} verification</span>
                  </div>
                </>
              )}
              <div className="ml-auto text-muted-foreground">
                {filteredVulns.length === 0 ? "–" : `${Math.round((confirmedVulns.length / filteredVulns.length) * 100)}% high-confidence`}
              </div>
            </div>
          )}

          {/* Confirmed findings */}
          {confirmedVulns.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-emerald-500/8 border border-emerald-500/20">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="text-sm font-bold text-emerald-400">Confirmed findings</span>
                <span className="ml-auto text-xs text-emerald-400/60 font-medium">{confirmedVulns.length} finding{confirmedVulns.length !== 1 ? "s" : ""} — high confidence, act on these</span>
              </div>
              {viewMode === "grouped" ? (
                <div className="space-y-2">
                  {Array.from(groupedConfirmedVulns.entries()).map(([cat, vulns]) => {
                    const priorCount = Array.from(groupedConfirmedVulns.entries())
                      .filter(([c]) => c < cat)
                      .reduce((sum, [, vs]) => sum + vs.length, 0);
                    return (
                      <CategorySection
                        key={cat}
                        category={cat}
                        vulns={vulns}
                        globalIndex={priorCount}
                        defaultOpen
                        rootUrl={report.targetUrl}
                      />
                    );
                  })}
                </div>
              ) : (
                <AnimatePresence mode="popLayout">
                  {confirmedVulns.map((v, i) => (
                    <VulnCard key={v.id} vuln={v} index={i} rootUrl={report.targetUrl} />
                  ))}
                </AnimatePresence>
              )}
            </div>
          )}

          {/* Needs verification */}
          {unverifiedVulns.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-amber-500/8 border border-amber-500/20">
                <HelpCircle className="w-4 h-4 text-amber-400 shrink-0" />
                <div className="min-w-0">
                  <span className="text-sm font-bold text-amber-400">Needs verification</span>
                  <span className="text-xs text-amber-400/60 ml-2 font-medium hidden sm:inline">— heuristic detections, confirm manually before acting</span>
                </div>
                <span className="ml-auto text-xs text-amber-400/60 font-medium shrink-0">{unverifiedVulns.length} finding{unverifiedVulns.length !== 1 ? "s" : ""}</span>
              </div>
              {viewMode === "grouped" ? (
                <div className="space-y-2">
                  {Array.from(groupedUnverifiedVulns.entries()).map(([cat, vulns]) => {
                    const priorCount = Array.from(groupedUnverifiedVulns.entries())
                      .filter(([c]) => c < cat)
                      .reduce((sum, [, vs]) => sum + vs.length, 0);
                    return (
                      <CategorySection
                        key={cat}
                        category={cat}
                        vulns={vulns}
                        globalIndex={priorCount}
                        needsVerification
                        defaultOpen
                        rootUrl={report.targetUrl}
                      />
                    );
                  })}
                </div>
              ) : (
                <AnimatePresence mode="popLayout">
                  {unverifiedVulns.map((v, i) => (
                    <VulnCard key={v.id} vuln={v} index={i} needsVerification rootUrl={report.targetUrl} />
                  ))}
                </AnimatePresence>
              )}
            </div>
          )}

          {filteredVulns.length === 0 && activeCategory && (
            <div className="text-center py-10 glass-card rounded-xl text-muted-foreground text-sm">
              No findings in this category.
            </div>
          )}

          {vulnerabilities.length === 0 && (
            <div className="text-center py-12 glass-card rounded-xl">
              <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto mb-4" />
              <h3 className="text-xl font-bold mb-2">No vulnerabilities found</h3>
              <p className="text-muted-foreground">Excellent work. Your application appears secure based on our checks.</p>
            </div>
          )}
        </div>

        {/* Right Col: Category sidebar + AI + Tech */}
        <div className="space-y-8">
          {/* Category breakdown */}
          {sortedCategories.length > 0 && (
            <div className="glass-card rounded-2xl p-6">
              <h3 className="text-sm font-bold mb-4 flex items-center gap-2 text-muted-foreground uppercase tracking-wider">
                <Filter className="w-4 h-4" /> Finding Categories
              </h3>
              <div className="space-y-1.5">
                <button
                  onClick={() => setActiveCategory(null)}
                  className={cn(
                    "w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors",
                    activeCategory === null
                      ? "bg-primary/20 text-primary border border-primary/30"
                      : "hover:bg-white/5 text-muted-foreground border border-transparent",
                  )}
                >
                  <span className="font-medium">All findings</span>
                  <span className="text-xs bg-secondary px-2 py-0.5 rounded-full">{vulnerabilities.length}</span>
                </button>
                {sortedCategories.map((cat) => {
                  const meta = getCategoryMeta(cat);
                  const count = categoryCounts[cat];
                  const isActive = activeCategory === cat;
                  return (
                    <button
                      key={cat}
                      onClick={() => setActiveCategory(isActive ? null : cat)}
                      className={cn(
                        "w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm transition-all text-left",
                        isActive
                          ? "bg-primary/10 border border-primary/30"
                          : "hover:bg-white/5 border border-transparent",
                      )}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className={meta.color}>{meta.icon}</span>
                        <span className={cn("truncate text-xs", isActive ? "text-foreground font-medium" : "text-muted-foreground")}>
                          {meta.label}
                        </span>
                      </div>
                      <span className={cn(
                        "shrink-0 text-xs font-bold rounded-full w-6 h-6 flex items-center justify-center",
                        isActive ? "bg-primary/20 text-primary" : "bg-secondary text-muted-foreground",
                      )}>{count}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* AI Analysis */}
          {aiAnalysis && (
            <div className="glass-card rounded-2xl p-6 border-t-4 border-t-primary">
              <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary" /> AI Analysis
              </h3>

              <div className="space-y-6">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Overall Risk</h4>
                  <p className="text-sm">{aiAnalysis.overallRisk}</p>
                </div>

                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Top Priorities</h4>
                  <ul className="space-y-2">
                    {aiAnalysis.topPriorities.map((p, i) => (
                      <li key={i} className="text-sm flex items-start gap-2">
                        <span className="text-primary mt-0.5">•</span> <span>{p}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Quick Wins</h4>
                  <ul className="space-y-2">
                    {aiAnalysis.quickWins.map((w, i) => (
                      <li key={i} className="text-sm flex items-start gap-2">
                        <span className="text-emerald-400 mt-0.5">✓</span> <span>{w}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {aiAnalysis.complianceNotes && (
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Compliance Notes</h4>
                    <p className="text-sm text-muted-foreground/80 leading-relaxed">{aiAnalysis.complianceNotes}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Fix with your AI agent */}
          {aiAnalysis?.agentFixPrompt && (
            <AgentFixPromptCard prompt={aiAnalysis.agentFixPrompt} detectedAgent={aiAnalysis.detectedAgent} />
          )}

          {/* Software Inventory */}
          <SoftwareInventoryCard technologies={technologies ?? []} vulnerabilities={vulnerabilities} />

          {/* Pages Scanned */}
          <PagesScannedCard rootUrl={report.targetUrl} pagesScanned={pagesScanned ?? []} probedNotFound={probedNotFound ?? []} />

          {/* Reconnaissance */}
          {recon && <ReconCard recon={recon} />}

          {/* Tech Profile */}
          <div className="glass-card rounded-2xl p-6">
            <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
              <Server className="w-5 h-5 text-muted-foreground" /> Tech Profile
            </h3>

            <div className="space-y-4">
              {tlsGrade && (
                <div className="flex items-center justify-between py-2 border-b border-white/5">
                  <span className="text-sm text-muted-foreground flex items-center gap-2"><Lock className="w-4 h-4" /> SSL/TLS Grade</span>
                  <span className={cn("font-bold", getGradeColor(tlsGrade))}>{tlsGrade}</span>
                </div>
              )}
              {server && (
                <div className="flex items-center justify-between py-2 border-b border-white/5">
                  <span className="text-sm text-muted-foreground">Server</span>
                  <span className="text-sm font-medium">{server}</span>
                </div>
              )}
              <div>
                <span className="text-sm text-muted-foreground mb-3 block">Detected Technologies</span>
                <div className="flex flex-wrap gap-2">
                  {technologies.map((t, i) => {
                    const { name, version } = parseTechVersion(t);
                    return (
                      <span key={i} className="inline-flex items-center gap-1 px-2.5 py-1 bg-secondary text-xs rounded-md border border-white/5">
                        <span>{name}</span>
                        {version && (
                          <span className="px-1.5 py-0.5 bg-yellow-500/15 text-yellow-400 text-[10px] font-mono rounded border border-yellow-500/20 leading-none">
                            {version}
                          </span>
                        )}
                      </span>
                    );
                  })}
                  {technologies.length === 0 && <span className="text-xs text-muted-foreground">None detected</span>}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Monitor CTA banner */}
      <div className="glass-panel rounded-2xl p-6 border border-indigo-500/25 bg-indigo-500/5 flex flex-col sm:flex-row items-center gap-6">
        <div className="w-12 h-12 rounded-xl bg-indigo-500/15 border border-indigo-500/25 flex items-center justify-center shrink-0">
          <Bell className="w-6 h-6 text-indigo-400" />
        </div>
        <div className="flex-1 text-center sm:text-left">
          <h3 className="font-bold text-lg mb-1">Keep watching this URL</h3>
          <p className="text-sm text-muted-foreground">
            Weekly automated rescans + instant CVE alerts when new vulnerabilities match your tech stack. <span className="text-indigo-400 font-semibold">$129/yr</span>
          </p>
        </div>
        <Link
          href="/monitor"
          className="shrink-0 px-6 py-3 bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-xl font-bold hover:bg-indigo-500/30 transition-all whitespace-nowrap flex items-center gap-2"
        >
          <Bell className="w-4 h-4" /> Start Monitoring
        </Link>
      </div>

      {/* Bottom CTA */}
      <div className="glass-panel rounded-3xl p-8 md:p-12 text-center border border-primary/20 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
        <Shield className="w-12 h-12 text-primary mx-auto mb-4" />
        <h2 className="text-2xl md:text-3xl font-bold mb-3">Scan another website</h2>
        <p className="text-muted-foreground mb-8 max-w-md mx-auto">
          Check a different URL, a staging environment, or a client's site — each scan takes under 10 minutes.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] hover:-translate-y-1 transition-all duration-300"
          >
            <Plus className="w-5 h-5" /> New Scan
          </Link>
          <CopyReportButton data={copyData} />
          <DownloadPDFButton data={{
            targetUrl: report.targetUrl,
            scannedAt: report.scannedAt,
            summary: copyData.summary,
            confirmedVulns: allConfirmedVulns,
            unverifiedVulns: allUnverifiedVulns,
            technologies: technologies ?? [],
            server: server ?? null,
            tlsGrade: tlsGrade ?? null,
            aiAnalysis: aiAnalysis ?? null,
            categoryCounts,
            pagesScanned: pagesScanned ?? [],
          }} />
          <ShareButton reportId={reportId} />
        </div>
      </div>
      </div>

      {/* ── Timed undo toast ── shown for 5s after a finding is dismissed ── */}
      {undoToast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 bg-background border border-border rounded-xl px-4 py-3 shadow-2xl text-sm animate-in slide-in-from-bottom-2 duration-200">
          <span className="text-muted-foreground">
            <span className="font-semibold text-foreground truncate max-w-[200px] inline-block align-bottom">{undoToast.vuln.name}</span>
            {" "}dismissed as false positive
          </span>
          <button
            onClick={async () => {
              if (undoToastTimerRef.current) clearTimeout(undoToastTimerRef.current);
              const toastVuln = undoToast.vuln;
              setUndoToast(null);
              await undismissFinding(toastVuln);
            }}
            className="text-primary hover:text-primary/80 font-bold underline underline-offset-2 shrink-0"
          >
            Undo
          </button>
        </div>
      )}
    </>
    </DismissalsContext.Provider>
  );
}


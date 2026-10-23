import type { ReportResponse, SortBy, ViewMode } from "./report-viewer-types";
import { Vulnerability } from "@workspace/api-client-react";
import { ShieldAlert, CheckCircle2, Filter, X, ArrowUpDown, HelpCircle } from "lucide-react";
import { cn, getSeverityColors } from "@/lib/utils";
import { CategoryPill } from "./report-viewer-categories";

export function FindingsHeading({ report, activeCategory, filteredVulns, visibleVulns, dismissedCount }: {
  report: ReportResponse;
  activeCategory: string | null;
  filteredVulns: Vulnerability[];
  visibleVulns: Vulnerability[];
  dismissedCount: number;
}) {
  return (
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
  );
}

/** Severity badges, split confirmed vs unverified. */
export function SeverityBadges({ confirmedSeverityCounts, unverifiedSeverityCounts }: {
  confirmedSeverityCounts: Record<string, number>;
  unverifiedSeverityCounts: Record<string, number>;
}) {
  return (
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
  );
}

/** Sort and view-mode toggles. */
export function SortViewToggles({ sortBy, setSortBy, viewMode, setViewMode }: {
  sortBy: SortBy;
  setSortBy: (s: SortBy) => void;
  viewMode: ViewMode;
  setViewMode: (v: ViewMode) => void;
}) {
  return (
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
  );
}

/** Category filter pills. */
export function CategoryFilterPills({ sortedCategories, categoryCounts, activeCategory, setActiveCategory }: {
  sortedCategories: string[];
  categoryCounts: Record<string, number>;
  activeCategory: string | null;
  setActiveCategory: (c: string | null) => void;
}) {
  return (
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
  );
}

/** How many of the shown findings are confirmed vs need verification. */
export function AccuracyBar({ filteredVulns, confirmedVulns, unverifiedVulns }: {
  filteredVulns: Vulnerability[];
  confirmedVulns: Vulnerability[];
  unverifiedVulns: Vulnerability[];
}) {
  return (
    <div className="flex items-center gap-4 p-3 rounded-xl bg-secondary/40 border border-white/5 text-xs">
      <div className="flex items-center gap-1.5 text-green-400 font-medium">
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
  );
}


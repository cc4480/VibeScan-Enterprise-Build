import { outdatedAnalysisNote } from "@/lib/fixed-findings";
import type { ReportPayload, AiAnalysisData } from "./report-viewer-types";
import { Vulnerability } from "@workspace/api-client-react";
import { Server, Lock, Activity, Filter } from "lucide-react";
import { cn, getGradeColor } from "@/lib/utils";
import { getCategoryMeta, parseTechVersion } from "./report-viewer-data";
import { CategoryBarChart } from "./report-viewer-charts";

/** Findings by category: bar chart plus a clickable list. */
export function CategoryBreakdownCard({ sortedCategories, categoryCounts, visibleVulns, activeCategory, setActiveCategory, vulnerabilities }: {
  sortedCategories: string[];
  categoryCounts: Record<string, number>;
  visibleVulns: Vulnerability[];
  activeCategory: string | null;
  setActiveCategory: (c: string | null) => void;
  vulnerabilities: Vulnerability[];
}) {
  return (
    <div className="glass-card rounded-2xl p-6">
      <h3 className="text-sm font-bold mb-4 flex items-center gap-2 text-muted-foreground uppercase tracking-wider">
        <Filter className="w-4 h-4" /> Finding Categories
      </h3>
      <div className="mb-5 pb-5 border-b border-white/5">
        <CategoryBarChart
          categoryCounts={categoryCounts}
          vulnerabilities={visibleVulns}
          activeCategory={activeCategory}
          onSelect={(cat) => setActiveCategory(activeCategory === cat ? null : cat)}
        />
      </div>
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
                <span style={{ color: meta.color }}>{meta.icon}</span>
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
  );
}

/** The written analysis: overall risk, priorities, quick wins, compliance notes. */
/** `fixedCount`: findings verified fixed since the scan; the analysis was written before them. */
export function AiAnalysisCard({ aiAnalysis, fixedCount = 0 }: { aiAnalysis: AiAnalysisData; fixedCount?: number }) {
  const outdated = outdatedAnalysisNote(fixedCount);
  return (
    <div className="glass-card rounded-2xl p-6 border-t-4 border-t-primary">
      <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
        <Activity className="w-5 h-5 text-primary" /> AI Analysis
      </h3>

      <div className="space-y-6">
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Overall Risk</h4>
          <p className="text-sm">{aiAnalysis.overallRisk}</p>
          {outdated && <p className="mt-2 text-xs text-amber-300/80">{outdated}</p>}
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
                <span className="text-green-400 mt-0.5">✓</span> <span>{w}</span>
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
  );
}

export function TechProfileCard({ tlsGrade, server, technologies }: {
  tlsGrade: ReportPayload["tlsGrade"];
  server: ReportPayload["server"];
  technologies: string[];
}) {
  return (
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
  );
}


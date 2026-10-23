/** Findings grouped by category, and the what's-new summary. */
import { ChevronDown } from "lucide-react";
import { cn, getSeverityColors } from "@/lib/utils";
import { useState } from "react";
import type { Vulnerability } from "@workspace/api-client-react";
import { getCategoryMeta, SEVERITY_ORDER } from "./report-viewer-data";
import { VulnCard } from "./report-viewer-vuln";
import { NEW_CATEGORY_LABELS } from "@/lib/summary-category-labels";

// ─── Grouped category section ─────────────────────────────────────────────────

/** How many information-only findings a group may hold before it starts closed. */
export const BULK_INFO_GROUP = 8;
export const isBulkInformation = (vulns: Vulnerability[]): boolean => vulns.length > BULK_INFO_GROUP && vulns.every((v) => v.severity === "info");

/** Findings drawn at first in an open group; the rest come with "Show more". A long page is slow and fragile to paint. */
export const GROUP_PAGE = 25;

export function CategorySection({
  category,
  vulns,
  defaultOpen = true,
  needsVerification = false,
  globalIndex,
  rootUrl,
}: {
  category: string;
  vulns: Vulnerability[];
  defaultOpen?: boolean;
  needsVerification?: boolean;
  globalIndex: number;
  rootUrl?: string;
}) {
  // A long group of information-only findings (the many fixture values in a repository's tests, say) starts closed: it
  // is context, not something to act on, and dozens of open cards make the page heavy to paint. One click opens it.
  const [open, setOpen] = useState(defaultOpen && !isBulkInformation(vulns));
  const [shownCount, setShownCount] = useState(GROUP_PAGE);
  const meta = getCategoryMeta(category);

  const highestSeverity = vulns.reduce<string | null>((acc, v) => {
    if (acc === null) return v.severity;
    return (SEVERITY_ORDER[v.severity] ?? 99) < (SEVERITY_ORDER[acc] ?? 99) ? v.severity : acc;
  }, null);

  return (
    <div className="rounded-xl overflow-hidden border border-white/5 bg-secondary/10" style={{ borderLeft: `3px solid ${meta.color}` }}>
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={`${meta.label} — ${vulns.length} finding${vulns.length !== 1 ? "s" : ""}, ${open ? "collapse" : "expand"}`}
        className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-white/[0.03] transition-colors text-left"
      >
        <span style={{ color: meta.color }}>{meta.icon}</span>
        <span className="font-bold text-sm text-foreground flex-1">{meta.label}</span>
        {highestSeverity && (
          <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border shrink-0", getSeverityColors(highestSeverity))}>
            {highestSeverity}
          </span>
        )}
        <span className="text-xs font-bold bg-secondary rounded-full w-6 h-6 flex items-center justify-center text-muted-foreground shrink-0">
          {vulns.length}
        </span>
        <ChevronDown className={cn("w-4 h-4 text-muted-foreground transition-transform shrink-0", open && "rotate-180")} />
      </button>

      {open && (
        <div className="px-3 pb-3 pt-1 space-y-2 border-t border-white/5">
          {vulns.slice(0, shownCount).map((v, i) => (
            <VulnCard
              key={v.id}
              vuln={v}
              index={globalIndex + i}
              needsVerification={needsVerification}
              rootUrl={rootUrl}
            />
          ))}
          {vulns.length > shownCount && (
            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <button
                onClick={() => setShownCount((n) => n + GROUP_PAGE)}
                className="px-4 py-2 rounded-lg text-sm font-semibold bg-secondary hover:bg-secondary/80 border border-white/10 transition-colors"
              >
                Show {Math.min(GROUP_PAGE, vulns.length - shownCount)} more
              </button>
              <button onClick={() => setShownCount(vulns.length)} className="text-sm text-muted-foreground hover:text-foreground underline underline-offset-2">
                Show all {vulns.length} ({vulns.length - shownCount} not shown)
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Category filter pill ─────────────────────────────────────────────────────

export function CategoryPill({
  category, count, active, onClick,
}: { category: string; count: number; active: boolean; onClick: () => void }) {
  const meta = getCategoryMeta(category);
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-all",
        active
          ? "bg-primary/15 border-primary/40 text-foreground"
          : "bg-secondary/50 border-white/5 text-muted-foreground hover:border-white/15 hover:text-foreground",
      )}
    >
      <span className={active ? "text-primary" : undefined} style={active ? undefined : { color: meta.color }}>{meta.icon}</span>
      <span>{meta.label}</span>
      <span className={cn(
        "ml-1 rounded-full px-1.5 py-0.5 font-bold",
        active ? "bg-primary/20 text-primary" : "bg-white/10 text-muted-foreground",
      )}>{count}</span>
    </button>
  );
}

// ─── Summary new-findings callout ─────────────────────────────────────────────


export function SummaryNewFindings({ categories }: { categories: Record<string, number> }) {
  const notable = Object.entries(NEW_CATEGORY_LABELS)
    .filter(([cat]) => (categories[cat] ?? 0) > 0)
    .map(([, label]) => label);

  if (notable.length === 0) return null;

  return (
    <div className="mt-4 p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 text-sm text-amber-200/80 leading-relaxed">
      <span className="font-semibold text-amber-300">Also detected: </span>
      {notable.join(", ")}.
    </div>
  );
}

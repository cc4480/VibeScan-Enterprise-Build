import type { ViewMode } from "./report-viewer-types";
import { Vulnerability } from "@workspace/api-client-react";
import { CheckCircle2, HelpCircle } from "lucide-react";
import { AnimatePresence } from "framer-motion";
import { VulnCard } from "./report-viewer-vuln";
import { CategorySection } from "./report-viewer-categories";

export function ConfirmedFindings({ confirmedVulns, viewMode, groupedConfirmedVulns, rootUrl }: {
  confirmedVulns: Vulnerability[];
  viewMode: ViewMode;
  groupedConfirmedVulns: Map<string, Vulnerability[]>;
  rootUrl: string;
}) {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-green-500/8 border border-green-500/20">
        <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
        <span className="text-sm font-bold text-green-400">Confirmed findings</span>
        <span className="ml-auto text-xs text-green-400/60 font-medium">{confirmedVulns.length} finding{confirmedVulns.length !== 1 ? "s" : ""} — high confidence, act on these</span>
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
                rootUrl={rootUrl}
              />
            );
          })}
        </div>
      ) : (
        <AnimatePresence mode="popLayout">
          {confirmedVulns.map((v, i) => (
            <VulnCard key={v.id} vuln={v} index={i} rootUrl={rootUrl} />
          ))}
        </AnimatePresence>
      )}
    </div>
  );
}

export function UnverifiedFindings({ unverifiedVulns, viewMode, groupedUnverifiedVulns, rootUrl }: {
  unverifiedVulns: Vulnerability[];
  viewMode: ViewMode;
  groupedUnverifiedVulns: Map<string, Vulnerability[]>;
  rootUrl: string;
}) {
  return (
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
                rootUrl={rootUrl}
              />
            );
          })}
        </div>
      ) : (
        <AnimatePresence mode="popLayout">
          {unverifiedVulns.map((v, i) => (
            <VulnCard key={v.id} vuln={v} index={i} needsVerification rootUrl={rootUrl} />
          ))}
        </AnimatePresence>
      )}
    </div>
  );
}

/** Shown when a filter matches nothing, or when the scan found nothing at all. */
export function EmptyFindings({ filteredVulns, activeCategory, vulnerabilities }: {
  filteredVulns: Vulnerability[];
  activeCategory: string | null;
  vulnerabilities: Vulnerability[];
}) {
  return (
    <>
      {filteredVulns.length === 0 && activeCategory && (
        <div className="text-center py-10 glass-card rounded-xl text-muted-foreground text-sm">
          No findings in this category.
        </div>
      )}

      {vulnerabilities.length === 0 && (
        <div className="text-center py-12 glass-card rounded-xl">
          <CheckCircle2 className="w-12 h-12 text-green-400 mx-auto mb-4" />
          <h3 className="text-xl font-bold mb-2">No findings from the tests that ran</h3>
          <p className="text-muted-foreground">
            Nothing to fix from what this scan checked. A clean result says nothing about the areas listed under
            &ldquo;What this scan tested&rdquo; as not tested.
          </p>
        </div>
      )}
    </>
  );
}

/** The compliance card and a finding row for the shared and owner report views. */
import { useState } from "react";
import { cn } from "@/lib/utils";
import { categoryHex } from "@/lib/category-colors";
import { ReproSteps } from "@/components/repro-steps";
import { SEV_COLORS, type SharedReportData } from "./shared-report-components";

/**
 * Renders `report.data.compliance` — which controls this scan's findings are
 * evidence for, grouped by framework. Renders nothing if the scan produced no
 * mappable findings (an honest empty state, not a hidden feature).
 *
 * The disclaimer is not optional trim: it is the thing that keeps this card
 * from being read as a compliance verdict. See lib/compliance.ts server-side.
 */
export function ComplianceCard({
  compliance,
}: {
  compliance?: SharedReportData["data"]["compliance"];
}) {
  if (!compliance || compliance.frameworks.length === 0) return null;

  return (
    <div className="glass-card rounded-2xl p-6 border-t-4 border-t-primary">
      <h3 className="text-lg font-bold mb-1 flex items-center gap-2">
        Compliance Mapping
      </h3>
      <p className="text-xs text-muted-foreground mb-6">
        Which findings are evidence for a recognised framework control — not a compliance verdict.
      </p>

      <div className="space-y-5">
        {compliance.frameworks.map((fw) => (
          <div key={fw.framework.id}>
            <div className="flex items-baseline gap-2 mb-2">
              <h4 className="text-sm font-bold">{fw.framework.name}</h4>
              <span className="text-[11px] text-muted-foreground">{fw.framework.version}</span>
            </div>
            <ul className="space-y-1.5 mb-2">
              {fw.controls.map((c) => (
                <li key={c.control} className="text-sm flex items-start gap-2">
                  <span className="text-primary mt-0.5 font-mono text-xs shrink-0">{c.control}</span>
                  <span className="flex-1">{c.title}</span>
                  <span className="text-xs text-muted-foreground shrink-0">
                    {c.findings} finding{c.findings === 1 ? "" : "s"}
                  </span>
                </li>
              ))}
            </ul>
            <p className="text-xs text-muted-foreground/70 leading-relaxed">{fw.framework.note}</p>
          </div>
        ))}
      </div>

      <p className="text-xs text-muted-foreground/60 leading-relaxed mt-6 pt-4 border-t border-border">
        {compliance.disclaimer}
      </p>
    </div>
  );
}

export function VulnRow({
  vuln,
  index,
  needsVerification,
}: {
  vuln: SharedReportData["data"]["vulnerabilities"][0];
  index: number;
  needsVerification?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEV_COLORS[vuln.severity] ?? SEV_COLORS.info;

  return (
    <div className="rounded-xl overflow-hidden border border-white/5 bg-secondary/10" style={{ borderLeft: `3px solid ${categoryHex(vuln.category)}` }}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 flex items-center gap-3 text-left hover:bg-white/[0.02] transition-colors"
      >
        <span className={cn("px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider shrink-0 border", sev)}>
          {vuln.severity}
        </span>
        <span className="font-semibold text-sm text-foreground flex-1 truncate">{index + 1}. {vuln.name}</span>
        {needsVerification && (
          <span className="text-[10px] px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded font-medium shrink-0 hidden sm:inline">
            verify
          </span>
        )}
        <span className="text-xs shrink-0 hidden md:inline" style={{ color: categoryHex(vuln.category) }}>{vuln.category}</span>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-0 border-t border-white/5 bg-secondary/20 space-y-4">
          <div className="pt-4">
            <p className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-1.5">Description</p>
            <p className="text-sm text-foreground/90 leading-relaxed">{vuln.description}</p>
          </div>

          {vuln.evidence && (
            <div>
              <p className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-1.5">Evidence</p>
              <div className="bg-background border border-white/10 rounded-lg p-3 text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap">
                {vuln.evidence}
              </div>
            </div>
          )}
          <ReproSteps evidence={vuln.evidence} dark />

          <div>
            <p className="text-xs font-bold text-primary uppercase tracking-wider mb-1.5">Recommended Fix</p>
            <div className="bg-primary/5 border border-primary/20 rounded-lg p-3 text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">
              {vuln.solution}
            </div>
          </div>

          {(vuln.cweId || vuln.cvssScore != null || vuln.wstgId) && (
            <div className="flex gap-2 flex-wrap">
              {vuln.cweId && (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace("CWE-", "")}.html`}
                  target="_blank" rel="noreferrer"
                  className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded hover:bg-secondary/80 transition-colors"
                >
                  {vuln.cweId}
                </a>
              )}
              {vuln.cvssScore != null && (
                <span className={cn(
                  "text-xs px-2 py-1 rounded font-medium",
                  vuln.cvssScore >= 9 ? "bg-red-950 text-red-400" :
                  vuln.cvssScore >= 7 ? "bg-orange-950 text-orange-400" :
                  vuln.cvssScore >= 4 ? "bg-yellow-950 text-yellow-400" :
                  "bg-secondary text-muted-foreground",
                )}>
                  CVSS {vuln.cvssScore.toFixed(1)}
                </span>
              )}
              {vuln.wstgId && (
                <span className="text-xs text-muted-foreground bg-secondary px-2 py-1 rounded">
                  {vuln.wstgId}
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

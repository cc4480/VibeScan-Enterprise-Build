import { useState } from "react";
import { AlertTriangle, CheckCircle2, MinusCircle } from "lucide-react";
import { cn, getGradeColor, formatSeverity } from "@/lib/utils";

export interface SharedReportData {
  id: string;
  scanId: string | null;
  targetUrl: string;
  tier: string;
  scannedAt: string;
  duration: number | null;
  createdAt: string;
  data: {
    vulnerabilities: Array<{
      id: string;
      name: string;
      severity: string;
      category: string;
      description: string;
      solution: string;
      evidence?: string | null;
      cweId?: string | null;
      cvssScore?: number | null;
      wstgId?: string | null;
      confidence?: number | null;
    }>;
    summary: {
      totalVulnerabilities: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
      riskScore: number;
      grade: string;
      /** True when a bot-protection layer answered; grade is "N/A" and the score is not meaningful. */
      intercepted?: boolean;
      executiveSummary: string;
    };
    technologies: string[];
    server?: string | null;
    tlsGrade?: string | null;
    aiAnalysis?: {
      overallRisk: string;
      topPriorities: string[];
      quickWins: string[];
      complianceNotes?: string | null;
    } | null;
    /** What ran, what was skipped and why. Absent on reports from before test records existed. */
    tests?: CoverageTest[] | null;
    compliance?: {
      frameworks: Array<{
        framework: { id: string; name: string; version: string; note: string };
        controls: Array<{ control: string; title: string; findings: number }>;
      }>;
      disclaimer: string;
    } | null;
  };
}

export const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-950 text-red-400 border-red-800",
  high:     "bg-orange-950 text-orange-400 border-orange-800",
  medium:   "bg-yellow-950 text-yellow-400 border-yellow-800",
  low:      "bg-blue-950 text-blue-400 border-blue-800",
  info:     "bg-zinc-900 text-zinc-400 border-zinc-700",
};

export const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

export const VERIFICATION_THRESHOLD = 65;

/** Hex fills for recharts — Tailwind classes don't reach into SVG fill/stroke,
 *  so this is the one place severity color is duplicated as a literal, kept in
 *  sync with SEV_COLORS above by eye since there are only five. */
export const SEVERITY_HEX: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#facc15",
  low: "#60a5fa",
  info: "#9ca3af",
};

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/** Findings by severity, as counts under the report summary. The header
 *  shows only the grade; a chart beside it was removed as clutter. */
export function SeverityLegend({ counts }: { counts: SeverityCounts }) {
  const sevs = (["critical", "high", "medium", "low", "info"] as const).filter((s) => counts[s] > 0);
  if (sevs.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1.5 justify-center sm:justify-start">
      {sevs.map((sev) => (
        <div key={sev} className="flex items-center gap-1.5 text-xs">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: SEVERITY_HEX[sev] }} />
          <span className="font-bold tabular-nums">{counts[sev]}</span>
          <span className="text-muted-foreground">{formatSeverity(sev)}</span>
        </div>
      ))}
    </div>
  );
}

export function GradeRing({ grade, score }: { grade: string; score: number }) {
  const colorMap: Record<string, string> = {
    A: "#4ade80", B: "#a3e635", C: "#facc15", D: "#fb923c", F: "#f87171",
  };
  // A scan a bot-protection layer answered carries no grade — the worker sets
  // it to "N/A". Its risk score is 0 only because the findings that would
  // deduct were withheld, so "Risk 0" here would read as a clean A. Render the
  // incomplete state instead: a neutral ring, a dash, and the word Incomplete.
  const graded = grade in colorMap;
  const color = graded ? colorMap[grade] : "#94a3b8";
  return (
    <div className="relative w-36 h-36 flex items-center justify-center shrink-0">
      <svg className="w-full h-full transform -rotate-90 absolute inset-0">
        <circle cx="68" cy="68" r="60" fill="none" stroke="currentColor" strokeWidth="6" className="text-secondary" />
        <circle
          cx="68" cy="68" r="60" fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${2 * Math.PI * 60}`}
          strokeDashoffset={`${2 * Math.PI * 60 * (1 - (graded ? score / 100 : 1))}`}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="flex flex-col items-center bg-background w-24 h-24 rounded-full border-4 border-card shadow-xl z-10 relative">
        <div className="flex flex-col items-center justify-center h-full">
          <span className={cn("text-4xl font-black leading-none", graded ? getGradeColor(grade) : "text-muted-foreground")}>
            {graded ? grade : "—"}
          </span>
          <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-widest mt-0.5">
            {graded ? `Risk ${score}` : "Incomplete"}
          </span>
        </div>
      </div>
    </div>
  );
}

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
    <div className="rounded-xl overflow-hidden border border-white/5 bg-secondary/10">
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
        <span className="text-xs text-muted-foreground shrink-0 hidden md:inline">{vuln.category}</span>
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


export interface CoverageTest {
  group: string;
  name: string;
  status: "ran" | "skipped" | "failed";
  findings: number;
  durationMs: number;
  reason?: string;
}

const isCoverageTest = (t: unknown): t is CoverageTest => {
  if (!t || typeof t !== "object") return false;
  const r = t as Record<string, unknown>;
  return typeof r.name === "string" && (r.status === "ran" || r.status === "skipped" || r.status === "failed");
};

/**
 * What the scan tested, and what it did not.
 *
 * A grade reads as "everything was checked". It was not: without verified
 * ownership every active test is skipped, and without a second login access
 * control is. This card says so beside the grade, so a clean result cannot be
 * taken as a statement about areas the scan never looked at. Reports from before
 * test records existed say that instead of implying full coverage.
 */
export function CoverageCard({ tests }: { tests?: CoverageTest[] | null }) {
  const list = Array.isArray(tests) ? tests.filter(isCoverageTest) : [];

  if (list.length === 0) {
    return (
      <div className="glass-card rounded-2xl p-6">
        <h3 className="text-lg font-bold mb-1">What this scan tested</h3>
        <p className="text-sm text-muted-foreground">
          Not recorded for this scan, which was run before test records were kept. Do not read the grade as a
          statement about full coverage.
        </p>
      </div>
    );
  }

  const ran = list.filter((t) => t.status === "ran");
  const skipped = list.filter((t) => t.status === "skipped");
  const failed = list.filter((t) => t.status === "failed");
  const notRun = list.filter((t) => t.status !== "ran");
  const groups = Array.from(new Set(list.map((t) => t.group)));

  return (
    <div className="glass-card rounded-2xl p-6">
      <h3 className="text-lg font-bold mb-1">What this scan tested</h3>
      <p className="text-sm text-muted-foreground mb-4">
        <span className="font-semibold text-foreground">
          {ran.length} of {list.length} tests ran
        </span>
        {skipped.length > 0 && `, ${skipped.length} skipped`}
        {failed.length > 0 && `, ${failed.length} failed`}.
      </p>

      {notRun.length > 0 ? (
        <>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
            Not tested on this scan
          </p>
          <ul className="space-y-2 mb-3">
            {notRun.map((t, i) => (
              <li key={`${t.name}-${i}`} className="text-sm flex items-start gap-2">
                {t.status === "failed" ? (
                  <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-amber-400" />
                ) : (
                  <MinusCircle className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
                )}
                <span className="flex-1">
                  <span className="font-medium">{t.name}</span>
                  <span className="block text-xs text-muted-foreground">
                    {t.status === "failed" ? `Failed to run${t.reason ? `: ${t.reason}` : ""}` : (t.reason ?? "Skipped")}
                  </span>
                </span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground/80 leading-relaxed">
            A clean result says nothing about these areas.
          </p>
        </>
      ) : (
        <p className="text-sm flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-green-400" /> Every test ran.
        </p>
      )}

      <details className="mt-4 group">
        <summary className="cursor-pointer text-xs text-primary hover:underline">All {list.length} tests</summary>
        <div className="mt-3 space-y-3">
          {groups.map((g) => (
            <div key={g}>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-1">{g}</p>
              <ul className="space-y-1">
                {list
                  .filter((t) => t.group === g)
                  .map((t, i) => (
                    <li key={`${t.name}-${i}`} className="text-xs flex items-baseline gap-2">
                      <span
                        className={cn(
                          "font-mono text-[10px] shrink-0 w-14",
                          t.status === "ran" ? "text-green-400" : t.status === "failed" ? "text-amber-400" : "text-muted-foreground",
                        )}
                      >
                        {t.status}
                      </span>
                      <span className="flex-1 min-w-0 break-words">{t.name}</span>
                      {t.status === "ran" && (
                        <span className="text-muted-foreground shrink-0">
                          {t.findings} finding{t.findings === 1 ? "" : "s"}
                        </span>
                      )}
                    </li>
                  ))}
              </ul>
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}

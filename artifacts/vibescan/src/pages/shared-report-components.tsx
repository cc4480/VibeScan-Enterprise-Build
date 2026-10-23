import { formatSeverity } from "@/lib/utils";
import { type CoverageTest } from "./shared-report-coverage";
export { ComplianceCard, VulnRow } from "./shared-report-cards";
export { CoverageCard, PrintCoverage, coverageMarkdown } from "./shared-report-coverage";
export type { CoverageTest } from "./shared-report-coverage";
export { SourceCodeCard, PrintSourceCode, sourceCodeMarkdown } from "./shared-report-source";

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
      /** The prompt written for the user's AI editor. */
      agentFixPrompt?: string | null;
      source?: "ai" | "template";
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

export { GradeRing } from "@/components/grade-ring";
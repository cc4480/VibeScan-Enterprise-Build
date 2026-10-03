/**
 * Reports saved before the server left the scan's own notes out of its totals (see scanNotes.ts)
 * carry totals that count them: "Total Findings: 2" over a list with one finding and one note. The
 * stored row is left as it is. This recounts from the stored list whenever a report is read, so
 * every page, print, copy and PDF that reads the summary agrees with the list under it.
 */
import { buildExecutiveSummary } from "./executiveSummary";
import { splitScanNotes } from "./scanNotes";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

type Counts = Record<string, number>;

function countBySeverity(items: readonly unknown[]): Counts {
  const counts: Counts = {};
  for (const v of items) {
    const sev = (v as { severity?: unknown } | null)?.severity;
    if (typeof sev === "string") counts[sev] = (counts[sev] ?? 0) + 1;
  }
  return counts;
}

/**
 * Returns the report data with its summary counts taken from the findings about the site. Returns
 * the same object when the stored counts already agree, or when the data is not a report with a
 * list and a summary. The executive summary is rewritten only when it is the text this server
 * writes from the stored counts, so a different text (a withheld scan's, say) is never replaced.
 */
export function withNoteFreeTotals<T>(data: T): T {
  if (typeof data !== "object" || data === null) return data;
  const d = data as { vulnerabilities?: unknown; summary?: unknown; targetUrl?: unknown };
  if (!Array.isArray(d.vulnerabilities)) return data;
  if (typeof d.summary !== "object" || d.summary === null) return data;
  const summary = d.summary as Record<string, unknown>;

  const { findings, notes } = splitScanNotes(d.vulnerabilities as unknown[]);
  if (notes.length === 0) return data;

  const counts = countBySeverity(findings);
  const next: Record<string, unknown> = { totalVulnerabilities: findings.length };
  for (const sev of SEVERITIES) next[sev] = counts[sev] ?? 0;

  const stale = Object.keys(next).some((k) => summary[k] !== next[k]);
  if (!stale) return data;

  const storedCounts: Counts = {};
  for (const sev of SEVERITIES) storedCounts[sev] = typeof summary[sev] === "number" ? (summary[sev] as number) : 0;
  const { grade, riskScore, executiveSummary, intercepted } = summary;
  if (
    !intercepted &&
    typeof grade === "string" &&
    typeof riskScore === "number" &&
    typeof executiveSummary === "string" &&
    typeof d.targetUrl === "string" &&
    typeof summary.totalVulnerabilities === "number" &&
    executiveSummary === buildExecutiveSummary(grade, riskScore, d.targetUrl, summary.totalVulnerabilities, storedCounts)
  ) {
    next.executiveSummary = buildExecutiveSummary(grade, riskScore, d.targetUrl, findings.length, counts);
  }

  return { ...(data as object), summary: { ...summary, ...next } } as T;
}

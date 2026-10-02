/**
 * The short form of a finished report, for GET /api/v1/scans/:id: enough for a CI
 * job to decide pass or fail without downloading every finding.
 *
 * Reads stored report data defensively (older reports lack fields) and never
 * invents a number: a field that is not there is left out, not zero. In
 * particular "coverage" reports what ran and what did not, because a grade with
 * skipped tests is not a statement about the skipped areas.
 */
import { countTests } from "./testLedger";
import { isScanNote } from "./scanNotes";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export interface ReportSummary {
  grade?: string;
  riskScore?: number;
  /** Findings about the site. The scan's own notes are not among them; see scanNotes. */
  findings?: Record<(typeof SEVERITIES)[number] | "total", number>;
  /** How many remarks the scan made about itself (a skipped test, a sign-in page that answered instead of the app). */
  scanNotes?: number;
  coverage?: { ran: number; skipped: number; failed: number; total: number };
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function summariseReport(data: unknown): ReportSummary {
  if (!isRecord(data)) return {};
  const out: ReportSummary = {};

  const summary = data["summary"];
  if (isRecord(summary)) {
    if (typeof summary["grade"] === "string") out.grade = summary["grade"];
    if (typeof summary["riskScore"] === "number") out.riskScore = summary["riskScore"];
  }

  const vulns = data["vulnerabilities"];
  if (Array.isArray(vulns)) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    let notes = 0;
    for (const v of vulns) {
      // A note is not a finding. Counted apart, so a scan that could only report notes (a sign-in
      // page answered) shows its notes instead of passing for clean to a job that reads the total.
      if (isScanNote(v)) {
        notes += 1;
        continue;
      }
      const sev = isRecord(v) ? String(v["severity"] ?? "").toLowerCase() : "";
      if ((SEVERITIES as readonly string[]).includes(sev)) counts[sev as (typeof SEVERITIES)[number]] += 1;
      counts.total += 1;
    }
    out.findings = counts;
    out.scanNotes = notes;
  }

  const tests = data["tests"];
  if (Array.isArray(tests) && tests.length > 0) {
    out.coverage = countTests(tests.filter(isRecord) as never);
  }
  return out;
}

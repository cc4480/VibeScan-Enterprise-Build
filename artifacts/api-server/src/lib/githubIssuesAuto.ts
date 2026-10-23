/**
 * File issues by itself when monitoring finds a new problem.
 *
 * Opt-in per account (Settings, GitHub issues). It only acts on regressions: findings the previous scan did not have, on a
 * scan where no extra tests ran (the worker decides that; see workerMonitor.ts). It files nothing below the severity the
 * account chose, at most MAX_PER_SCAN a scan, and goes through fileIssue, so the one-issue-per-problem rule, the secret
 * redaction and the daily cap all hold exactly as for a click. It never throws: a failure here must not fail the scan.
 */
import { eq } from "drizzle-orm";
import { db, reportsTable } from "@workspace/db";
import { findingFingerprint } from "./fingerprint";
import { fileIssue, getDestination, type AutoSeverity } from "./githubIssues";
import type { Log } from "./workerTypes";

export const MAX_PER_SCAN = 10;
const RANK: Record<string, number> = { medium: 2, high: 3, critical: 4 };
const rankOf = (severity: string) => RANK[severity.toLowerCase()] ?? 0;

/** The regressions at or above the floor, most severe first, and no more than MAX_PER_SCAN. */
export function selectForFiling<T extends { severity: string }>(regressions: readonly T[], floor: AutoSeverity): T[] {
  return regressions
    .filter((r) => rankOf(r.severity) >= RANK[floor]!)
    .sort((a, b) => rankOf(b.severity) - rankOf(a.severity))
    .slice(0, MAX_PER_SCAN);
}

export async function autoFileRegressions(input: {
  userId: string;
  reportId: string;
  regressions: ReadonlyArray<{ category: string; name: string; evidence?: string | null; severity: string }>;
  log: Log;
}): Promise<void> {
  const { userId, reportId, regressions, log } = input;
  try {
    const dest = await getDestination(userId);
    if (!dest?.autoFile) return;
    const chosen = selectForFiling(regressions, dest.autoMinSeverity);
    if (chosen.length === 0) return;

    // Ids come from the stored report, the same place a click on the finding reads them.
    const [report] = await db.select({ data: reportsTable.data }).from(reportsTable).where(eq(reportsTable.id, reportId));
    const vulns = (report?.data as { vulnerabilities?: Array<{ id?: string; category: string; name: string; evidence?: string | null }> } | undefined)?.vulnerabilities ?? [];
    const idByFingerprint = new Map(vulns.filter((v) => v.id).map((v) => [findingFingerprint(v.category, v.name, v.evidence), v.id!]));

    for (const r of chosen) {
      const findingId = idByFingerprint.get(findingFingerprint(r.category, r.name, r.evidence));
      if (!findingId) continue;
      const result = await fileIssue({ userId, reportId, findingId });
      if (result.ok) {
        log.info({ reportId, issue: result.issueNumber, created: result.created }, "GitHub issue filed automatically");
      } else {
        log.warn({ reportId, code: result.code }, "Automatic GitHub issue not filed");
        // A rejected token, a missing permission or the daily cap will not clear within this scan: stop asking.
        break;
      }
    }
  } catch (err) {
    log.warn({ err }, "Automatic GitHub issue filing failed (non-fatal)");
  }
}

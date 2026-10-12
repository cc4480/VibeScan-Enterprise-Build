import { shortDate, type VerificationStatus } from "./verify-fix";

/**
 * What a report does with findings the owner has since verified as fixed.
 *
 * A report is a snapshot of one scan: its grade and its AI analysis were written
 * when the scan ran, and are not recomputed. But the open lists and counts should
 * not keep telling the reader to "act on" something that is already done, so a
 * finding whose latest re-check says "fixed" moves out of them into a section of
 * its own. Only the server's verdict counts: "not_rechecked" and "failed" are
 * never treated as fixed (see verify-fix.ts).
 */

/** The most recent verification of each finding, by creation time. */
function latestPerFinding(list: readonly VerificationStatus[] | undefined): VerificationStatus[] {
  const latest = new Map<string, VerificationStatus>();
  for (const v of list ?? []) {
    const prior = latest.get(v.findingId);
    if (!prior || Date.parse(v.createdAt) >= Date.parse(prior.createdAt)) latest.set(v.findingId, v);
  }
  return [...latest.values()];
}

/** Ids of the findings whose latest re-check found them fixed. */
export function fixedFindingIds(list: readonly VerificationStatus[] | undefined): Set<string> {
  return new Set(latestPerFinding(list).filter((v) => v.verdict === "fixed").map((v) => v.findingId));
}

/** When the most recent of those fixes was verified, as an ISO string, or null if none. */
export function latestFixDate(list: readonly VerificationStatus[] | undefined): string | null {
  const dates = latestPerFinding(list)
    .filter((v) => v.verdict === "fixed" && v.completedAt)
    .map((v) => v.completedAt as string)
    .sort((a, b) => Date.parse(b) - Date.parse(a));
  return dates[0] ?? null;
}

/** The cover's severity counts with the fixed findings taken out. Never below zero. */
export function subtractFixed<T extends Record<string, number>>(counts: T, fixed: readonly { severity: string }[]): T {
  const out: Record<string, number> = { ...counts };
  for (const f of fixed) {
    if (f.severity in out) out[f.severity] = Math.max(0, out[f.severity] - 1);
  }
  return out as T;
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/** The line on the cover. It says what changed and what did not. */
export function fixedNotice(count: number, latestIso: string | null): string | null {
  if (count <= 0) return null;
  const when = shortDate(latestIso);
  return `${count} ${plural(count, "finding", "findings")} verified fixed since this scan${when ? ` (${when})` : ""}. The grade and the AI analysis describe the scan as it ran.`;
}

/** The note under the AI analysis, which was written before the fixes. */
export function outdatedAnalysisNote(count: number): string | null {
  if (count <= 0) return null;
  return `Written when the scan ran. ${count} ${plural(count, "finding has", "findings have")} since been verified fixed, so parts of this may no longer apply.`;
}

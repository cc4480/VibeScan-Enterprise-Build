/**
 * Scan notes: the scan's own remarks about itself, which are not findings about the site.
 *
 * The scanner records "Active security testing was skipped for this scan", "Scan reached a sign-in
 * page, not the app" and the like as findings of category "Scan Coverage", at Info severity and high
 * confidence, so that they travel with the report. They are true and worth reading. They are not
 * vulnerabilities, and listing them under "Confirmed findings ... act on these" told an owner that
 * the scan had confirmed something in their site. Every report surface keeps them apart, under
 * "About this scan", and counts only the other findings as findings.
 */

/** The category the scanner gives its notes (see scannerCoverage.ts in the API server). */
export const SCAN_NOTE_CATEGORY = "Scan Coverage";

export const isScanNote = (v: { category: string }): boolean => v.category === SCAN_NOTE_CATEGORY;

/** Split a report's list into findings about the site and the scan's own notes, keeping each list's order. */
export function splitScanNotes<T extends { category: string }>(items: readonly T[]): { findings: T[]; notes: T[] } {
  const findings: T[] = [];
  const notes: T[] = [];
  for (const v of items) (isScanNote(v) ? notes : findings).push(v);
  return { findings, notes };
}

/**
 * Whether a card offers the actions that belong to a finding: "Check my fix" and "Mark as false
 * positive". A note is not a finding. The server refuses "Check my fix" on one ("That finding was not
 * found in your report"), and there is nothing in the owner's site to mark as a false positive.
 */
export const hasFindingActions = (v: { category: string }): boolean => !isScanNote(v);

export const SCAN_NOTES_TITLE = "About this scan";

/** The line under the heading, for every surface that lists the notes. */
export const SCAN_NOTES_BLURB = "Notes on what this scan could and could not check. They describe the scan, not your site.";

export const scanNotesCount = (n: number): string => `${n} note${n === 1 ? "" : "s"}`;

/**
 * What to say when a scan reported no findings but left notes about itself. A green "nothing found"
 * would read as a clean result, and a scan that was stopped by a sign-in page, or that skipped its
 * active tests, has not earned one.
 */
export const NO_FINDINGS_WITH_NOTES = {
  title: "No findings were reported",
  body: `Read the notes under “${SCAN_NOTES_TITLE}” before treating that as a clean result: they say what the scan could not check.`,
} as const;

/**
 * The Markdown copy's section for the notes, as lines. `format` writes one note the way the copy
 * writes a finding. When the report has no findings, the section is led by "No findings were
 * reported", so a pasted copy cannot be read as a clean result.
 */
export function scanNotesMarkdown<T extends { category: string }>(
  notes: readonly T[],
  hasFindings: boolean,
  format: (note: T, position: number) => string,
): string[] {
  if (notes.length === 0) return [];
  const lines: string[] = [];
  if (!hasFindings) lines.push(`## ${NO_FINDINGS_WITH_NOTES.title}`, ``, NO_FINDINGS_WITH_NOTES.body, ``);
  lines.push(`## ℹ️ ${SCAN_NOTES_TITLE} (${notes.length})`, ``, `> ${SCAN_NOTES_BLURB}`, ``);
  notes.forEach((v, i) => lines.push(format(v, i + 1), ``));
  return lines;
}

/**
 * Scan notes: the scan's own remarks about itself ("Active security testing was skipped for this
 * scan", "Scan reached a sign-in page, not the app"). The scanner records them as Info findings in
 * the category "Scan Coverage", so that they travel with the report. They are not findings about
 * the site, so no total, count or list of findings includes them. The report pages keep them apart
 * under "About this scan" (artifacts/vibescan/src/lib/scan-notes.ts); this is the server's side of
 * the same rule.
 */

/** The category the scanner gives its notes (see scannerCoverage.ts). */
export const SCAN_NOTE_CATEGORY = "Scan Coverage";

/** Reads stored report data too, so anything that is not an object of that category counts as a finding. */
export const isScanNote = (v: unknown): boolean =>
  typeof v === "object" && v !== null && (v as { category?: unknown }).category === SCAN_NOTE_CATEGORY;

/** Splits a report's list into findings about the site and the scan's own notes, keeping each list's order. */
export function splitScanNotes<T>(items: readonly T[]): { findings: T[]; notes: T[] } {
  const findings: T[] = [];
  const notes: T[] = [];
  for (const v of items) (isScanNote(v) ? notes : findings).push(v);
  return { findings, notes };
}

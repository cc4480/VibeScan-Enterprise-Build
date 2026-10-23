/**
 * The words on the "since your last scan" card. The comparison is made on the server
 * (lib/scanDiff.ts) under one rule: a finding that vanished is only "fixed" if the
 * test that would have found it ran again. This file only decides what is shown.
 */

export interface ChangeFinding {
  name: string;
  severity: string;
  category: string;
}

export interface ScanChanges {
  since: { scanId: string | null; scannedAt: string | null };
  unchanged: number;
  added: ChangeFinding[];
  firstSeen: ChangeFinding[];
  fixed: ChangeFinding[];
  notRechecked: ChangeFinding[];
  newlyRun: string[];
  noLongerRun: string[];
  differentAccess: boolean;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "20 Sep", the same on every machine. */
export function shortDate(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
}

export interface ChangeGroup {
  key: "new" | "firstSeen" | "fixed" | "notRechecked";
  label: string;
  tone: "warn" | "good" | "neutral";
  /** One line explaining what the group does and does not mean. Empty when the label says it all. */
  note: string;
  items: ChangeFinding[];
}

/** The groups worth showing, in the order to show them, with their honest explanations. Empty groups are left out. */
export function changeGroups(c: ScanChanges): ChangeGroup[] {
  const groups: ChangeGroup[] = [
    { key: "new", label: `${c.added.length} new`, tone: "warn", note: "", items: c.added },
    {
      key: "firstSeen",
      label: `${c.firstSeen.length} first seen`,
      tone: "warn",
      note: "These come from tests that did not run last time, so they may have been there all along.",
      items: c.firstSeen,
    },
    { key: "fixed", label: `${c.fixed.length} fixed`, tone: "good", note: "Each was found last time, and the test that found it ran again and did not.", items: c.fixed },
    {
      key: "notRechecked",
      label: `${c.notRechecked.length} not re-checked`,
      tone: "neutral",
      note: "Found last time, but not checked again this time: the test behind them did not run, or the file they were in was not read. That is not the same as fixed.",
      items: c.notRechecked,
    },
  ];
  return groups.filter((g) => g.items.length > 0);
}

/** True when there is anything to say about the comparison. */
export function hasChanges(c: ScanChanges): boolean {
  return changeGroups(c).length > 0 || c.newlyRun.length > 0 || c.differentAccess;
}

export function headline(c: ScanChanges): string {
  const when = shortDate(c.since.scannedAt);
  return when ? `Since your last scan (${when})` : "Since your last scan";
}

/** The sentence when nothing changed, so the card can say so plainly instead of vanishing. */
export function unchangedSentence(c: ScanChanges): string {
  return c.unchanged > 0 ? `Nothing new and nothing fixed. ${c.unchanged} finding${c.unchanged === 1 ? "" : "s"} carried over.` : "Nothing found either time.";
}

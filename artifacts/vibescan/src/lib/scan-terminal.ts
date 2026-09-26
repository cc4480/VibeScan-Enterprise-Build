/**
 * What the scan terminal shows, and how fast.
 *
 * Every line is a test the scanner really finished (the same ledger the report
 * prints as "what this scan tested"). Nothing here invents a result. The only
 * thing this file decides is pacing: tests finish in bursts, often a dozen in the
 * first second, far faster than anyone can read, so they are revealed one at a
 * time. That delays the display, never the scan, and never changes a line.
 */

export interface LiveTest {
  group: string;
  name: string;
  status: "ran" | "skipped" | "failed";
  findings: number;
  durationMs: number;
  reason?: string;
}

export type RowTone = "clean" | "finding" | "skipped" | "failed";

export interface TerminalRow {
  mark: string;
  tone: RowTone;
  group: string;
  name: string;
  /** The outcome in words, right-hand column. */
  result: string;
}

/** One test as a terminal row. Skips and failures say why: they are never shown as passes. */
export function toRow(t: LiveTest): TerminalRow {
  if (t.status === "skipped") {
    // The scanner's long wording is for the report; here the reader needs what to do about it.
    const why = t.reason?.startsWith("domain not verified") ? "verify this domain to run it" : (t.reason ?? "no reason recorded");
    return { mark: "–", tone: "skipped", group: t.group, name: t.name, result: `not run: ${why}` };
  }
  if (t.status === "failed") {
    return { mark: "✗", tone: "failed", group: t.group, name: t.name, result: `did not run: ${t.reason ?? "unknown error"}` };
  }
  if (t.findings > 0) {
    return { mark: "!", tone: "finding", group: t.group, name: t.name, result: `${t.findings} ${t.findings === 1 ? "finding" : "findings"}` };
  }
  return { mark: "✓", tone: "clean", group: t.group, name: t.name, result: "no issues found" };
}

/**
 * The order tests are shown in. Skipped tests are recorded up front, before any
 * test has run, so shown in arrival order they bury the real results under a wall
 * of "not run". They are held back until the scan is over and listed after, under
 * their own heading. Same tests, same outcomes, only the order differs.
 */
export function orderForDisplay(tests: LiveTest[], scanOver: boolean): LiveTest[] {
  const active = tests.filter((t) => t.status !== "skipped");
  return scanOver ? [...active, ...tests.filter((t) => t.status === "skipped")] : active;
}

/**
 * Milliseconds before the next waiting test is shown. Readable when the backlog
 * is small, faster only when it is large enough that a slow pace would leave the
 * page still replaying long after the scan ended (about 20 seconds at most).
 */
export function revealDelayMs(waiting: number): number {
  if (waiting > 40) return 320;
  if (waiting > 25) return 450;
  return 620;
}

/** The scanner runs about this many tests; only used to shape the progress bar. */
export const EXPECTED_TESTS = 40;

/** Bar position from what is actually on screen, so it never runs ahead of the lines. */
export function progressPercent(status: string, revealed: number): number {
  if (status === "complete") return 100;
  if (status === "failed") return 0;
  if (["queued", "paid", "pending"].includes(status)) return Math.min(8, 2 + revealed);
  const scanning = 10 + Math.round((Math.min(revealed, EXPECTED_TESTS) / EXPECTED_TESTS) * 78);
  return status === "analyzing" ? Math.max(scanning, 92) : Math.min(scanning, 88);
}

export const rowColor: Record<RowTone, string> = {
  clean: "text-green-400/90",
  finding: "text-amber-300",
  skipped: "text-zinc-500",
  failed: "text-amber-400",
};

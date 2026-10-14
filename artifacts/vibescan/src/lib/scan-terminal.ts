/**
 * What the scan terminal shows, and how fast.
 *
 * Every line is real: a test the scanner finished, or one of the checks inside it
 * with what became of it (lib/checkOutcomes.ts on the server decides that, and only
 * ever calls a check clear when it is certain). Nothing here invents a result. The
 * only thing decided here is pacing: tests finish in bursts, far faster than anyone
 * can read, so lines are revealed one at a time. That delays the display, never the
 * scan, and never changes a line.
 */

export interface LiveCheck {
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | "varies";
  outcome: "clear" | "finding" | "checked" | "not_run";
  category?: string;
}

export interface LiveTest {
  group: string;
  name: string;
  status: "ran" | "skipped" | "failed";
  findings: number;
  durationMs: number;
  reason?: string;
  /** Finding category, for colour. Null for a step with no findings of its own. */
  category?: string | null;
  /** Real numbers for the line ("168 of 544 read"), for steps whose outcome alone says too little. */
  detail?: string;
  checks?: LiveCheck[];
}

export type RowTone = "clean" | "finding" | "skipped" | "failed" | "neutral";

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
    return { mark: "!", tone: "finding", group: t.group, name: t.name, result: `${t.findings} ${t.findings === 1 ? "finding" : "findings"}${t.detail ? ` · ${t.detail}` : ""}` };
  }
  return { mark: "✓", tone: "clean", group: t.group, name: t.name, result: t.detail ?? "no issues found" };
}

/** One check inside a test. "checked" means it ran but a finding could not be placed, so it is not called clear. */
export function toCheckRow(c: LiveCheck): { mark: string; tone: RowTone; result: string } {
  switch (c.outcome) {
    case "clear":
      return { mark: "✓", tone: "clean", result: "clear" };
    case "finding":
      return { mark: "!", tone: "finding", result: "FOUND" };
    case "checked":
      return { mark: "·", tone: "neutral", result: "checked" };
    default:
      return { mark: "–", tone: "skipped", result: "not run" };
  }
}

/** What the terminal steps through: each test, then the checks inside it. */
export type TerminalItem = { kind: "test"; test: LiveTest } | { kind: "check"; test: LiveTest; check: LiveCheck };

export function flattenItems(tests: LiveTest[]): TerminalItem[] {
  return tests.flatMap<TerminalItem>((test) => [
    { kind: "test", test },
    ...(test.checks ?? []).map<TerminalItem>((check) => ({ kind: "check", test, check })),
  ]);
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

/** Milliseconds a test row stays before the next line, and a check row. Readable, not fast. */
export const TEST_MS = 700;
export const CHECK_MS = 140;

/**
 * Delay before the next waiting line. Faster only when the backlog is large enough
 * that this pace would leave the page still replaying long after the scan ended.
 */
export function revealDelayMs(item: TerminalItem, waiting: number): number {
  const base = item.kind === "test" ? TEST_MS : CHECK_MS;
  return waiting > 260 ? Math.round(base * 0.5) : base;
}

export interface Tally {
  tests: number;
  ran: number;
  skipped: number;
  failed: number;
  clear: number;
  finding: number;
  checked: number;
  notRun: number;
  /** Checks in a full scan that no recorded test accounts for: said, never hidden. */
  unrecorded: number;
}

/** The closing numbers. clear + finding + checked + notRun + unrecorded is always the total. */
export function tally(tests: LiveTest[], totalChecks: number): Tally {
  const count = (s: LiveTest["status"]) => tests.filter((t) => t.status === s).length;
  const outcomes = tests.flatMap((t) => t.checks ?? []);
  const n = (o: LiveCheck["outcome"]) => outcomes.filter((c) => c.outcome === o).length;
  const accounted = outcomes.length;
  return {
    tests: tests.length,
    ran: count("ran"),
    skipped: count("skipped"),
    failed: count("failed"),
    clear: n("clear"),
    finding: n("finding"),
    checked: n("checked"),
    notRun: n("not_run"),
    unrecorded: Math.max(0, totalChecks - accounted),
  };
}

/** A repository scan shows about this many steps (listing, reading in stages, five checks); only shapes the progress bar. */
export const EXPECTED_REPO_STEPS = 14;

/** The scanner runs about this many tests; only used to shape the progress bar. */
export const EXPECTED_TESTS = 40;

/** Bar position from what is actually on screen, so it never runs ahead of the lines. */
export function progressPercent(status: string, revealedTests: number, expectedTests = EXPECTED_TESTS): number {
  if (status === "complete") return 100;
  if (status === "failed") return 0;
  if (["queued", "paid", "pending"].includes(status)) return Math.min(8, 2 + revealedTests);
  const scanning = 10 + Math.round((Math.min(revealedTests, expectedTests) / expectedTests) * 78);
  return status === "analyzing" ? Math.max(scanning, 92) : Math.min(scanning, 88);
}

export const rowColor: Record<RowTone, string> = {
  clean: "text-green-400/90",
  finding: "text-amber-300",
  skipped: "text-zinc-500",
  failed: "text-amber-400",
  neutral: "text-zinc-400",
};

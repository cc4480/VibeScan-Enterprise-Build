/**
 * A record of every test a scan was meant to run, and what became of it.
 *
 * Without it, "did every test run?" could only be inferred: a test that ran and
 * found nothing, one that was skipped (domain not verified, no second account,
 * no callback host) and one that crashed all left the same trace — no findings.
 * The ledger names each one with its outcome, time and finding count, so the
 * worker can log a line per test and the report can say what was covered.
 *
 * Recording never changes a result: `track` hands back exactly what the test
 * returned, and re-throws what it threw, so existing failure handling is
 * untouched.
 */
import type { ScanVulnerability } from "./scanner";

export type TestStatus = "ran" | "skipped" | "failed";

/** What a probe hands back when it can tell "found nothing" from "had nothing to test". */
export interface ProbeOutcome {
  findings: ScanVulnerability[];
  /** Set when nothing was actually tested: why. Ignored when there are findings. */
  notTested?: string;
}

export interface TestRecord {
  /** The group the test belongs to, e.g. "HTTP probes" or "active". */
  group: string;
  name: string;
  status: TestStatus;
  findings: number;
  durationMs: number;
  /** Why it was skipped or how it failed. */
  reason?: string;
  /** The names of the findings it raised, so a check-by-check view can say which check fired. */
  found?: string[];
}

/**
 * A list of records that tells a listener about each one as it is added, however
 * it is added: the scanner records some tests through track() and pushes others
 * straight onto the list. Species is plain Array so filter()/map() on it do not
 * build another observed list.
 */
class ObservedRecords extends Array<TestRecord> {
  static override get [Symbol.species]() {
    return Array;
  }
  listener?: (record: TestRecord) => void;
  override push(...items: TestRecord[]): number {
    const length = super.push(...items);
    for (const item of items) this.listener?.(item);
    return length;
  }
}

export class TestLedger {
  readonly records: TestRecord[];

  /** `onRecord` hears every test as it is recorded: how a running scan shows real progress. */
  constructor(onRecord?: (record: TestRecord) => void) {
    const records = new ObservedRecords();
    if (onRecord) records.listener = onRecord;
    this.records = records;
  }

  /**
   * Time a test that has already started (the promise is created by the
   * caller, so tests keep running in parallel), and record its outcome.
   */
  track(group: string, name: string, run: Promise<ScanVulnerability[]>): Promise<ScanVulnerability[]> {
    const started = Date.now();
    return run.then(
      (found) => {
        this.records.push({
          group, name, status: "ran", findings: found.length, durationMs: Date.now() - started,
          ...(found.length > 0 ? { found: found.slice(0, 40).map((v) => v.name) } : {}),
        });
        return found;
      },
      (err: unknown) => {
        this.records.push({
          group,
          name,
          status: "failed",
          findings: 0,
          durationMs: Date.now() - started,
          reason: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200),
        });
        throw err;
      },
    );
  }

  /**
   * Like track(), for a probe that can say it tested nothing. A probe that returns [] when it had
   * no endpoint to try, no record to compare or no reply it could read looks exactly like one that
   * tried and found nothing, and this ledger would record both as "ran, 0 findings". Such a probe
   * returns notTested with its reason and is recorded as skipped instead. Findings always win: a
   * probe that found something obviously tested something.
   */
  trackOutcome(group: string, name: string, run: Promise<ProbeOutcome>): Promise<ScanVulnerability[]> {
    const started = Date.now();
    return run.then(
      ({ findings, notTested }) => {
        if (notTested && findings.length === 0) {
          this.records.push({ group, name, status: "skipped", findings: 0, durationMs: Date.now() - started, reason: notTested });
          return findings;
        }
        this.records.push({
          group, name, status: "ran", findings: findings.length, durationMs: Date.now() - started,
          ...(findings.length > 0 ? { found: findings.slice(0, 40).map((v) => v.name) } : {}),
        });
        return findings;
      },
      (err: unknown) => {
        this.records.push({
          group, name, status: "failed", findings: 0, durationMs: Date.now() - started,
          reason: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200),
        });
        throw err;
      },
    );
  }

  skip(group: string, name: string, reason: string): void {
    this.records.push({ group, name, status: "skipped", findings: 0, durationMs: 0, reason });
  }

  summary(): { ran: number; skipped: number; failed: number; total: number } {
    const count = (s: TestStatus) => this.records.filter((r) => r.status === s).length;
    return { ran: count("ran"), skipped: count("skipped"), failed: count("failed"), total: this.records.length };
  }
}

/** One console line per test, e.g. "[test] RAN     injection (XSS, SQLi) — 0 findings, 2140 ms". */
export function formatTestLine(r: TestRecord): string {
  const status = r.status.toUpperCase().padEnd(7);
  const detail =
    r.status === "skipped"
      ? `skipped: ${r.reason ?? "no reason recorded"}`
      : r.status === "failed"
        ? `failed after ${r.durationMs} ms: ${r.reason ?? "unknown error"}`
        : `${r.findings} finding${r.findings === 1 ? "" : "s"}, ${r.durationMs} ms`;
  return `[test] ${status} ${r.group} · ${r.name} — ${detail}`;
}

/** The closing line, e.g. "[tests] 34 ran, 3 skipped, 0 failed (37 total)". */
/** Counts, for places that only have room for a number (the report-ready email). */
export function countTests(records: TestRecord[]): { ran: number; skipped: number; failed: number; total: number } {
  const n = (s: TestStatus) => records.filter((r) => r.status === s).length;
  return { ran: n("ran"), skipped: n("skipped"), failed: n("failed"), total: records.length };
}

export function formatTestSummary(records: TestRecord[]): string {
  const n = (s: TestStatus) => records.filter((r) => r.status === s).length;
  return `[tests] ${n("ran")} ran, ${n("skipped")} skipped, ${n("failed")} failed (${records.length} total)`;
}

/** Why the verified-domain tests did not run. One wording, used everywhere. */
export const NOT_VERIFIED = "domain not verified for this account (active tests need proof of ownership)";

export const isTestRecord = (t: unknown): t is TestRecord => {
  if (!t || typeof t !== "object") return false;
  const r = t as Record<string, unknown>;
  return typeof r["name"] === "string" && (r["status"] === "ran" || r["status"] === "skipped" || r["status"] === "failed");
};

/**
 * "What this scan tested", as plain text for an editor reading the report.
 *
 * A grade on its own reads as "everything was checked". It is not: a scan without
 * verified ownership skips every active test, and one without a second login skips
 * access control. This says so next to the grade, and lists what was not tested so
 * that a clean result is never read as a statement about those areas.
 *
 * Takes `unknown` because it reads stored report data: older reports have no record
 * at all, and that is stated rather than papered over.
 */
export function coverageLines(tests: unknown): string[] {
  const list = Array.isArray(tests) ? tests.filter(isTestRecord) : [];
  if (list.length === 0) {
    return [
      "What this scan tested: not recorded (this scan predates test records). Do not read the grade as a statement about full coverage.",
      "",
    ];
  }
  const n = (s: TestStatus) => list.filter((t) => t.status === s).length;
  const ran = n("ran");
  const notRun = list.filter((t) => t.status !== "ran");
  if (notRun.length === 0) return [`What this scan tested: all ${list.length} tests ran.`, ""];

  const CAP = 25;
  const lines = [
    `What this scan tested: ${ran} of ${list.length} tests ran, ${n("skipped")} skipped, ${n("failed")} failed.`,
    "Not tested on this scan — a clean result says nothing about these:",
    ...notRun.slice(0, CAP).map(
      (t) => `- ${t.name}${t.group ? ` (${t.group})` : ""}: ${t.status === "failed" ? `failed to run${t.reason ? ` — ${t.reason}` : ""}` : (t.reason ?? "skipped")}`,
    ),
  ];
  if (notRun.length > CAP) lines.push(`- …and ${notRun.length - CAP} more.`);
  lines.push("");
  return lines;
}

/** A test's identity without its per-scan counts: "site crawl (12 inner pages)" -> "site crawl". */
function testIdentity(r: { group?: unknown; name?: unknown }): string {
  return `${String(r.group ?? "")}::${String(r.name ?? "").replace(/\s*\([^)]*\)\s*$/, "")}`;
}

/**
 * Tests that ran on this scan but did not run on the previous one.
 *
 * Regression detection needs it: a finding absent last time is only a
 * regression if the test that finds it RAN last time. When a domain is verified
 * between two scans, every active test runs for the first time, and without
 * this each of their findings was reported as a check that "started failing".
 *
 * Returns [] when the previous scan kept no ledger (older reports), so the
 * comparison falls back to what it did before rather than claiming anything.
 */
export function newlyRunTests(previous: unknown, current: TestRecord[]): string[] {
  if (!Array.isArray(previous) || previous.length === 0) return [];
  const ranBefore = new Set(
    previous
      .filter((r): r is { group: unknown; name: unknown; status: unknown } => !!r && typeof r === "object")
      .filter((r) => r.status === "ran")
      .map(testIdentity),
  );
  return current
    .filter((r) => r.status === "ran" && !ranBefore.has(testIdentity(r)))
    .map((r) => r.name);
}

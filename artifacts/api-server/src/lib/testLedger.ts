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

export interface TestRecord {
  /** The group the test belongs to, e.g. "HTTP probes" or "active". */
  group: string;
  name: string;
  status: TestStatus;
  findings: number;
  durationMs: number;
  /** Why it was skipped or how it failed. */
  reason?: string;
}

export class TestLedger {
  readonly records: TestRecord[] = [];

  /**
   * Time a test that has already started (the promise is created by the
   * caller, so tests keep running in parallel), and record its outcome.
   */
  track(group: string, name: string, run: Promise<ScanVulnerability[]>): Promise<ScanVulnerability[]> {
    const started = Date.now();
    return run.then(
      (found) => {
        this.records.push({ group, name, status: "ran", findings: found.length, durationMs: Date.now() - started });
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
export function formatTestSummary(records: TestRecord[]): string {
  const n = (s: TestStatus) => records.filter((r) => r.status === s).length;
  return `[tests] ${n("ran")} ran, ${n("skipped")} skipped, ${n("failed")} failed (${records.length} total)`;
}

/** Why the verified-domain tests did not run. One wording, used everywhere. */
export const NOT_VERIFIED = "domain not verified for this account (active tests need proof of ownership)";

const isTestRecord = (t: unknown): t is TestRecord => {
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

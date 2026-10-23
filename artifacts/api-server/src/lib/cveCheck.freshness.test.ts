import { describe, it, expect, beforeEach } from "vitest";
import { Writable } from "node:stream";
import pino from "pino";
import { warnIfLocalDataStale } from "./cveCheck";
import { setEolCache } from "./eolFetcherData";

/** A real logger whose output is captured, so the test reads what was actually logged at warn level. */
function capturedLogger() {
  const lines: Array<{ level: number; msg: string }> = [];
  const log = pino({ level: "debug" }, new Writable({ write(chunk, _enc, cb) { lines.push(JSON.parse(String(chunk))); cb(); } }));
  return { log, warnings: () => lines.filter((l) => l.level === 40).map((l) => l.msg).join("\n"), warned: () => lines.some((l) => l.level === 40) };
}

/** The live EOL refresh, as the nightly job leaves it in the in-process cache. */
const refreshedAt = (iso: string) =>
  setEolCache({ phpEol: {}, nginxEolCycles: new Set(), apacheEolCycles: new Set(), fetchedAt: new Date(iso) });

describe("warnIfLocalDataStale", () => {
  // Each test sets the live refresh time itself; the clock is passed in rather than waited for.
  beforeEach(() => refreshedAt("2020-01-01T00:00:00Z"));

  // The regression this file exists for. The nightly endoflife.date job kept the EOL half fresh, and because both
  // halves shared one "effective date", that reset the clock on the hand-maintained CVE tables as well, so the warning
  // that exists to nag about them stayed silent for as long as the daily job kept succeeding.
  it("warns about the hand-maintained tables even when the EOL refresh is fresh", () => {
    // Bundled tables last reviewed 2026-09-21; well past the 90-day threshold.
    refreshedAt("2027-01-20T03:00:00Z");
    const c = capturedLogger();
    warnIfLocalDataStale({ now: Date.parse("2027-01-20T12:00:00Z"), log: c.log });

    expect(c.warned()).toBe(true);
    expect(c.warnings()).toMatch(/hand-maintained cve tables/i);
    // The EOL half is genuinely fresh, so it must not also complain.
    expect(c.warnings()).not.toMatch(/EOL data is \d+ days old/i);
  });

  it("warns about EOL data when the nightly job has stopped running", () => {
    refreshedAt("2026-01-01T03:00:00Z");
    const c = capturedLogger();
    warnIfLocalDataStale({ now: Date.parse("2027-01-20T12:00:00Z"), log: c.log });

    expect(c.warnings()).toMatch(/EOL data is \d+ days old/i);
  });

  it("stays silent when both halves are inside the threshold", () => {
    // A date shortly after the bundled review date keeps both halves fresh.
    refreshedAt("2026-10-05T03:00:00Z");
    const c = capturedLogger();
    warnIfLocalDataStale({ now: Date.parse("2026-10-05T12:00:00Z"), log: c.log });

    expect(c.warned()).toBe(false);
  });

  it("uses the real clock and logger when none are given", () => {
    // Today is well inside 90 days of the bundled review, and the call must simply not throw.
    refreshedAt(new Date().toISOString());
    expect(() => warnIfLocalDataStale()).not.toThrow();
  });
});

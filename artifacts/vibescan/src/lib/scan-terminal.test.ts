import { describe, it, expect } from "vitest";
import { toRow, orderForDisplay, revealDelayMs, progressPercent, EXPECTED_TESTS, type LiveTest } from "./scan-terminal";

const test = (over: Partial<LiveTest>): LiveTest => ({
  group: "passive",
  name: "CORS policy",
  status: "ran",
  findings: 0,
  durationMs: 40,
  ...over,
});

describe("toRow: every line reflects the test's real outcome", () => {
  it("shows a clean pass only for a test that ran and found nothing", () => {
    expect(toRow(test({}))).toMatchObject({ mark: "✓", tone: "clean", result: "no issues found" });
  });

  it("shows findings, with the right plural", () => {
    expect(toRow(test({ findings: 1 })).result).toBe("1 finding");
    expect(toRow(test({ findings: 3 })).result).toBe("3 findings");
    expect(toRow(test({ findings: 3 })).tone).toBe("finding");
  });

  it("never shows a skipped test as a pass, and says why", () => {
    const row = toRow(test({ status: "skipped", reason: "no second account supplied" }));
    expect(row.tone).toBe("skipped");
    expect(row.mark).not.toBe("✓");
    expect(row.result).toBe("not run: no second account supplied");
  });

  it("turns the ownership skip into what to do about it", () => {
    const reason = "domain not verified for this account (active tests need proof of ownership)";
    expect(toRow(test({ status: "skipped", reason })).result).toBe("not run: verify this domain to run it");
  });

  it("never shows a test that crashed as a pass", () => {
    const row = toRow(test({ status: "failed", reason: "timed out" }));
    expect(row.tone).toBe("failed");
    expect(row.mark).not.toBe("✓");
    expect(row.result).toBe("did not run: timed out");
  });

  it("does not show a clean pass for a skipped test even if a stale finding count is attached", () => {
    expect(toRow(test({ status: "skipped", findings: 0 })).tone).not.toBe("clean");
  });

  it("copes with a missing reason", () => {
    expect(toRow(test({ status: "skipped" })).result).toContain("no reason recorded");
    expect(toRow(test({ status: "failed" })).result).toContain("unknown error");
  });
});

describe("orderForDisplay: real results first, what was not run after", () => {
  const ran = (name: string) => test({ name });
  const skipped = (name: string) => test({ name, status: "skipped", reason: "x" });
  const failed = (name: string) => test({ name, status: "failed", reason: "boom" });

  it("holds skipped tests back while the scan is running", () => {
    const tests = [skipped("s1"), ran("a"), skipped("s2"), ran("b")];
    expect(orderForDisplay(tests, false).map((t) => t.name)).toEqual(["a", "b"]);
  });

  it("lists them after everything that ran once the scan is over, and drops none", () => {
    const tests = [skipped("s1"), ran("a"), failed("f"), skipped("s2"), ran("b")];
    const shown = orderForDisplay(tests, true);
    expect(shown.map((t) => t.name)).toEqual(["a", "f", "b", "s1", "s2"]);
    expect(shown).toHaveLength(tests.length);
  });

  it("keeps a test that failed among the active ones: it is never hidden with the skips", () => {
    expect(orderForDisplay([failed("f")], false).map((t) => t.name)).toEqual(["f"]);
  });
});

describe("revealDelayMs: slow enough to read, fast enough not to lag the scan", () => {
  it("is readable when few tests are waiting", () => {
    expect(revealDelayMs(1)).toBeGreaterThanOrEqual(600);
    expect(revealDelayMs(12)).toBeGreaterThanOrEqual(600);
  });

  it("speeds up as the backlog grows, never getting faster than a glance", () => {
    expect(revealDelayMs(30)).toBeLessThan(revealDelayMs(5));
    expect(revealDelayMs(60)).toBeLessThan(revealDelayMs(30));
    expect(revealDelayMs(500)).toBeGreaterThanOrEqual(300);
  });

  it("clears a full 40-test burst in about 20 seconds at most", () => {
    let total = 0;
    for (let waiting = 40; waiting > 0; waiting--) total += revealDelayMs(waiting);
    expect(total).toBeLessThan(25_000);
    expect(total).toBeGreaterThan(12_000);
  });
});

describe("progressPercent follows what is on screen", () => {
  it("starts low, never claims completion early, and reaches 100 only when complete", () => {
    expect(progressPercent("queued", 0)).toBeLessThan(10);
    expect(progressPercent("scanning", 0)).toBeLessThan(15);
    expect(progressPercent("scanning", EXPECTED_TESTS)).toBeLessThan(100);
    expect(progressPercent("scanning", 500)).toBeLessThanOrEqual(88);
    expect(progressPercent("analyzing", 0)).toBeGreaterThanOrEqual(92);
    expect(progressPercent("analyzing", 500)).toBeLessThan(100);
    expect(progressPercent("complete", 0)).toBe(100);
  });

  it("only moves forward as lines are shown", () => {
    let last = 0;
    for (let n = 0; n <= EXPECTED_TESTS; n++) {
      const p = progressPercent("scanning", n);
      expect(p).toBeGreaterThanOrEqual(last);
      last = p;
    }
  });

  it("shows no progress for a failed scan", () => {
    expect(progressPercent("failed", 30)).toBe(0);
  });
});

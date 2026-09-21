import { describe, it, expect } from "vitest";
import { nextScanDelayDays, computeNextScanAt } from "./monitorScheduler";

/**
 * The rescan cadence is a published claim — secscan.info tells people an A is
 * rechecked every 14 days and an F every 3 — and it decides how often we spend
 * a customer's scan budget and send traffic at their site. It had no tests.
 *
 * Getting it wrong is quiet in both directions: too slow and monitoring reports
 * stale results nobody questions, too fast and it burns budget while hammering
 * a target. Neither shows up as an error.
 */

describe("nextScanDelayDays", () => {
  it("matches the cadence published on secscan.info", () => {
    expect(nextScanDelayDays("A")).toBe(14);
    expect(nextScanDelayDays("B")).toBe(7);
    expect(nextScanDelayDays("C")).toBe(7);
    expect(nextScanDelayDays("D")).toBe(3);
    expect(nextScanDelayDays("F")).toBe(3);
  });

  it("gets worse-graded sites rescanned sooner, never later", () => {
    // The property that actually matters, independent of the exact numbers:
    // cadence must be monotonic in risk.
    const order = ["A", "B", "C", "D", "F"].map(nextScanDelayDays);
    for (let i = 1; i < order.length; i++) {
      expect(order[i]!).toBeLessThanOrEqual(order[i - 1]!);
    }
  });
});

describe("nextScanDelayDays — grades outside A-F", () => {
  /**
   * A scan a bot-protection layer answered is graded "N/A": the worker withheld
   * every content-derived finding, so nothing was learned about the site.
   *
   * It falls through to the 3-day branch — the most aggressive cadence there is.
   * That is recorded here rather than changed, because it is a product decision
   * and not obviously wrong in either direction: retrying sooner is reasonable
   * when a scan produced nothing, but a target that blocks the scanner will keep
   * blocking it, so this spends a scan every 3 days, indefinitely, to learn
   * nothing each time. Flagged in the test report; if it is ever changed, this
   * test is what will catch it.
   */
  it("treats an ungraded (bot-intercepted) scan as the most urgent cadence", () => {
    expect(nextScanDelayDays("N/A")).toBe(3);
  });

  it("falls back to the most urgent cadence for anything unrecognised", () => {
    // Fail-closed: an unexpected grade should not silently mean "rescan in a
    // fortnight", which is what an A-shaped default would do.
    expect(nextScanDelayDays("")).toBe(3);
    expect(nextScanDelayDays("Z")).toBe(3);
    expect(nextScanDelayDays("a")).toBe(3); // case-sensitive by design
  });
});

describe("computeNextScanAt", () => {
  const from = new Date("2026-09-20T12:00:00.000Z");

  it("adds exactly the cadence for the grade", () => {
    expect(computeNextScanAt("A", from).toISOString()).toBe("2026-10-04T12:00:00.000Z");
    expect(computeNextScanAt("C", from).toISOString()).toBe("2026-09-27T12:00:00.000Z");
    expect(computeNextScanAt("F", from).toISOString()).toBe("2026-09-23T12:00:00.000Z");
  });

  it("always schedules into the future", () => {
    for (const grade of ["A", "B", "C", "D", "F", "N/A"]) {
      expect(computeNextScanAt(grade, from).getTime(), grade).toBeGreaterThan(from.getTime());
    }
  });

  it("does not mutate the date it was given", () => {
    const original = from.getTime();
    computeNextScanAt("A", from);
    expect(from.getTime()).toBe(original);
  });

  it("crosses a DST boundary without drifting off the expected instant", () => {
    // Fixed millisecond arithmetic, so the result is exactly 14 * 24h later
    // even across a local clock change. Asserted because a future switch to a
    // calendar-aware library would silently shift every scheduled rescan.
    const beforeDst = new Date("2026-10-25T00:30:00.000Z");
    const expected = beforeDst.getTime() + 14 * 24 * 60 * 60 * 1000;
    expect(computeNextScanAt("A", beforeDst).getTime()).toBe(expected);
  });
});

import { describe, it, expect } from "vitest";
import {
  nextScanDelayDays,
  computeNextScanAt,
  isSubscriptionDue,
  selectNewCveMatches,
} from "./monitorScheduler";

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
    const order = ["A", "B", "C", "D", "F"].map((g) => nextScanDelayDays(g));
    for (let i = 1; i < order.length; i++) {
      expect(order[i]!).toBeLessThanOrEqual(order[i - 1]!);
    }
  });
});

describe("nextScanDelayDays — an owner-chosen interval", () => {
  it("replaces the grade cadence after a graded scan, either way", () => {
    expect(nextScanDelayDays("A", { intervalDays: 3 })).toBe(3);
    expect(nextScanDelayDays("F", { intervalDays: 30 })).toBe(30);
  });

  it("is not used after a scan that was intercepted (N/A): that retries at the short cadence", () => {
    expect(nextScanDelayDays("N/A", { intervalDays: 30 })).toBe(3);
  });

  it("never beats the free-plan floor", () => {
    expect(nextScanDelayDays("A", { intervalDays: 3, minDays: 7 })).toBe(7);
    expect(nextScanDelayDays("A", { intervalDays: 14, minDays: 7 })).toBe(14);
  });

  it("null or absent keeps the grade cadence", () => {
    expect(nextScanDelayDays("A", { intervalDays: null })).toBe(14);
    expect(nextScanDelayDays("B", {})).toBe(7);
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

describe("isSubscriptionDue — the decision that makes rescans automatic", () => {
  const now = new Date("2026-09-20T12:00:00.000Z");
  const past = (days: number) => new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  const future = (days: number) => new Date(now.getTime() + days * 24 * 60 * 60 * 1000);

  it("is due once nextScanAt has passed", () => {
    expect(isSubscriptionDue({ expiresAt: future(300), nextScanAt: past(1), lastScanAt: past(8) }, now)).toBe(true);
  });

  it("is not due while nextScanAt is still in the future", () => {
    expect(isSubscriptionDue({ expiresAt: future(300), nextScanAt: future(1), lastScanAt: past(1) }, now)).toBe(false);
  });

  it("is never due once the subscription has expired, even if nextScanAt says otherwise", () => {
    expect(isSubscriptionDue({ expiresAt: past(1), nextScanAt: past(5), lastScanAt: past(8) }, now)).toBe(false);
  });

  it("once plans are enforced, the 1-year expiresAt no longer ends a paying customer's monitor", () => {
    // Month 13 of a monthly plan: the plan (checked by entitlement) decides, not the creation-time date.
    expect(isSubscriptionDue({ expiresAt: past(30), nextScanAt: past(1), lastScanAt: past(8) }, now, false)).toBe(true);
  });

  it("is due for a subscription that has never been scanned and has no cadence set", () => {
    // The exact shape of a subscription the moment POST /monitor/subscriptions
    // inserts it — before its baseline scan has finished — MUST still read as
    // due once nextScanAt is genuinely absent (the legacy/no-cadence case),
    // or a subscription could stall forever with nothing to advance it.
    expect(isSubscriptionDue({ expiresAt: future(300), nextScanAt: null, lastScanAt: null }, now)).toBe(true);
  });

  it("without a cadence, is not due again within 7 days of the last scan", () => {
    expect(isSubscriptionDue({ expiresAt: future(300), nextScanAt: null, lastScanAt: past(3) }, now)).toBe(false);
  });

  it("without a cadence, becomes due again after 7 days", () => {
    expect(isSubscriptionDue({ expiresAt: future(300), nextScanAt: null, lastScanAt: past(8) }, now)).toBe(true);
  });

  it("closes the race this function was pulled out to fix: a fresh subscription with a sentinel nextScanAt is not due yet", () => {
    // routes/monitor.ts sets nextScanAt = now + 3 days at creation, precisely
    // so a subscription whose baseline scan is still in flight does not also
    // read as "due" to this same day's sweep tick. Before that fix, this exact
    // shape — no lastScanAt, no nextScanAt — returned true here, and a sweep
    // landing between subscribe and baseline-scan-completion double-enqueued.
    const justCreated = { expiresAt: future(300), nextScanAt: future(3), lastScanAt: null };
    expect(isSubscriptionDue(justCreated, now)).toBe(false);
  });
});

/**
 * The CVE check moved from daily to hourly so a vulnerability matching a
 * customer's stack is not sitting unreported for most of a day. That is only
 * viable if the same match does not alert twice — the lookback window overlaps
 * the schedule on purpose, so every CVE is seen on several consecutive runs.
 *
 * Getting this wrong is not a crash. It is a paying customer receiving the same
 * email twenty-four times a day, and a full rescan fired at their site each
 * time.
 */
describe("selectNewCveMatches — what makes an hourly CVE check safe", () => {
  const match = (id: string, tech = "nginx") => ({ cve: { id }, matchedTech: tech });

  it("returns every match when nothing has been alerted yet", () => {
    const matches = [match("CVE-2026-0001"), match("CVE-2026-0002")];
    expect(selectNewCveMatches(matches, [])).toEqual(matches);
  });

  it("drops a CVE this subscription was already told about", () => {
    const fresh = selectNewCveMatches(
      [match("CVE-2026-0001"), match("CVE-2026-0002")],
      ["CVE-2026-0001"],
    );
    expect(fresh.map((m) => m.cve.id)).toEqual(["CVE-2026-0002"]);
  });

  it("returns nothing when every match is already known", () => {
    // The common case on the second and every subsequent hourly run. Nothing
    // should be emailed and no rescan should be enqueued.
    const fresh = selectNewCveMatches(
      [match("CVE-2026-0001"), match("CVE-2026-0002")],
      ["CVE-2026-0002", "CVE-2026-0001"],
    );
    expect(fresh).toEqual([]);
  });

  it("collapses a CVE that matched two technologies in ONE run", () => {
    // The case a database check cannot catch: the already-alerted set is read
    // before any of this run's rows are written, so a repeat inside a single
    // batch would be inserted twice and counted twice in the email.
    const fresh = selectNewCveMatches(
      [
        match("CVE-2026-0001", "nginx 1.24"),
        match("CVE-2026-0001", "nginx"),
        match("CVE-2026-0002"),
      ],
      [],
    );

    expect(fresh.map((m) => m.cve.id)).toEqual(["CVE-2026-0001", "CVE-2026-0002"]);
    // The first match wins: matchCvesToTechnologies returns the most specific
    // technology first, and that is the more useful one to show.
    expect(fresh[0]!.matchedTech).toBe("nginx 1.24");
  });

  it("preserves the order it was given", () => {
    // The caller sorts by EPSS x severity before this runs, so reordering here
    // would silently demote the most exploitable CVE out of the email's summary.
    const ids = ["CVE-2026-0009", "CVE-2026-0003", "CVE-2026-0007"];
    const fresh = selectNewCveMatches(ids.map((id) => match(id)), []);
    expect(fresh.map((m) => m.cve.id)).toEqual(ids);
  });

  it("does not mutate the array it was given", () => {
    const matches = [match("CVE-2026-0001"), match("CVE-2026-0002")];
    selectNewCveMatches(matches, ["CVE-2026-0001"]);
    expect(matches).toHaveLength(2);
  });
});

describe("nextScanDelayDays — the free-site floor", () => {
  it("holds a D or F grade to the floor instead of rescanning every 3 days", () => {
    expect(nextScanDelayDays("F", { minDays: 7 })).toBe(7);
    expect(nextScanDelayDays("D", { minDays: 7 })).toBe(7);
  });

  it("does not shorten a cadence that is already longer than the floor", () => {
    expect(nextScanDelayDays("A", { minDays: 7 })).toBe(14);
    expect(nextScanDelayDays("B", { minDays: 7 })).toBe(7);
  });

  it("changes nothing when no floor is passed, which is a paid plan", () => {
    expect(["A", "B", "C", "D", "F"].map((g) => nextScanDelayDays(g))).toEqual([14, 7, 7, 3, 3]);
  });

  it("applies the floor to the date computeNextScanAt returns", () => {
    const from = new Date("2026-10-03T00:00:00Z");
    expect(computeNextScanAt("F", from, { minDays: 7 }).toISOString()).toBe("2026-10-10T00:00:00.000Z");
    expect(computeNextScanAt("F", from).toISOString()).toBe("2026-10-06T00:00:00.000Z");
  });
});

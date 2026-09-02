import { describe, it, expect, afterEach, vi } from "vitest";
import { SlidingWindowLimiter, scanRateLimitRules } from "./rateLimit";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("SlidingWindowLimiter", () => {
  it("allows up to the limit and blocks the next request", () => {
    const l = new SlidingWindowLimiter([{ windowMs: HOUR, max: 3, label: "hour" }]);
    const t = 1_000_000;
    expect(l.check("a", t).allowed).toBe(true);
    expect(l.check("a", t + 1).allowed).toBe(true);
    expect(l.check("a", t + 2).allowed).toBe(true);

    const blocked = l.check("a", t + 3);
    expect(blocked.allowed).toBe(false);
    expect(blocked.rule?.label).toBe("hour");
  });

  it("keys buckets independently per caller", () => {
    const l = new SlidingWindowLimiter([{ windowMs: HOUR, max: 1, label: "hour" }]);
    const t = 1_000_000;
    expect(l.check("a", t).allowed).toBe(true);
    expect(l.check("a", t).allowed).toBe(false);
    // A different address is unaffected by the first one's exhaustion.
    expect(l.check("b", t).allowed).toBe(true);
  });

  it("lets capacity return as hits age out of the window", () => {
    const l = new SlidingWindowLimiter([{ windowMs: HOUR, max: 2, label: "hour" }]);
    const t = 1_000_000;
    l.check("a", t);
    l.check("a", t + 1000);
    expect(l.check("a", t + 2000).allowed).toBe(false);

    // Just after the first hit leaves the window, one slot frees up.
    expect(l.check("a", t + HOUR + 1).allowed).toBe(true);
    // But the second hit is still inside it.
    expect(l.check("a", t + HOUR + 2).allowed).toBe(false);
  });

  it("does not count blocked requests, so retry time cannot be pushed out", () => {
    const l = new SlidingWindowLimiter([{ windowMs: HOUR, max: 1, label: "hour" }]);
    const t = 1_000_000;
    l.check("a", t);

    const first = l.check("a", t + 1000);
    expect(first.allowed).toBe(false);

    // Hammering while blocked must not extend the wait: the retry time still
    // derives from the one counted hit, so it shrinks as real time passes.
    const later = l.check("a", t + 60_000);
    expect(later.allowed).toBe(false);
    expect(later.retryAfterSeconds!).toBeLessThan(first.retryAfterSeconds!);
  });

  it("reports a retry time that actually frees capacity", () => {
    const l = new SlidingWindowLimiter([{ windowMs: HOUR, max: 1, label: "hour" }]);
    const t = 1_000_000;
    l.check("a", t);
    const blocked = l.check("a", t + 5000);
    expect(blocked.allowed).toBe(false);

    const retryAt = t + 5000 + blocked.retryAfterSeconds! * 1000;
    expect(l.check("a", retryAt).allowed).toBe(true);
  });

  it("blocks on the stricter rule when several apply", () => {
    const l = new SlidingWindowLimiter([
      { windowMs: HOUR, max: 5, label: "hour" },
      { windowMs: DAY, max: 6, label: "day" },
    ]);
    const t = 1_000_000;
    for (let i = 0; i < 5; i++) expect(l.check("a", t + i).allowed).toBe(true);

    // Hourly cap trips first.
    expect(l.check("a", t + 10).rule?.label).toBe("hour");

    // An hour later the hourly window has cleared but the daily cap has one
    // slot left, then blocks.
    expect(l.check("a", t + HOUR + 100).allowed).toBe(true);
    expect(l.check("a", t + HOUR + 200).rule?.label).toBe("day");
  });

  it("drops idle buckets on prune", () => {
    const l = new SlidingWindowLimiter([{ windowMs: HOUR, max: 5, label: "hour" }]);
    const t = 1_000_000;
    l.check("a", t);
    l.check("b", t);
    expect(l.size()).toBe(2);

    l.prune(t + 1000);
    expect(l.size()).toBe(2);

    l.prune(t + HOUR + 1);
    expect(l.size()).toBe(0);
  });

  it("rejects an empty rule set rather than silently allowing everything", () => {
    expect(() => new SlidingWindowLimiter([])).toThrow();
  });
});

describe("scanRateLimitRules", () => {
  it("defaults to 5/hour and 20/day", () => {
    const rules = scanRateLimitRules();
    expect(rules.map((r) => [r.label, r.max])).toEqual([
      ["hour", 5],
      ["day", 20],
    ]);
  });

  it("honours the env overrides", () => {
    vi.stubEnv("SCAN_LIMIT_PER_HOUR", "2");
    vi.stubEnv("SCAN_LIMIT_PER_DAY", "9");
    expect(scanRateLimitRules().map((r) => r.max)).toEqual([2, 9]);
  });

  it("falls back to the defaults on unusable values", () => {
    for (const bad of ["0", "-1", "abc", "1.5", ""]) {
      vi.stubEnv("SCAN_LIMIT_PER_HOUR", bad);
      expect(scanRateLimitRules()[0]!.max).toBe(5);
    }
  });
});

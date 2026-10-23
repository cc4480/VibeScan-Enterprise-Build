import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { runPulse, summariseUptime, certDaysRemaining } from "./monitorPulse";

describe("summariseUptime", () => {
  it("returns nulls rather than zero when nothing has been checked", () => {
    // Zero percent uptime and "not checked yet" are very different things to
    // put in front of somebody.
    expect(summariseUptime([])).toEqual({ uptimePct: null, medianResponseMs: null, checks: 0 });
  });

  it("reports 100% when every check succeeded", () => {
    const summary = summariseUptime([
      { reachable: true, responseTimeMs: 100 },
      { reachable: true, responseTimeMs: 200 },
    ]);
    expect(summary.uptimePct).toBe(100);
    expect(summary.checks).toBe(2);
  });

  it("reports one failure in twenty-four as 95.8%", () => {
    const pulses = Array.from({ length: 24 }, (_, i) => ({
      reachable: i !== 5,
      responseTimeMs: i !== 5 ? 150 : null,
    }));
    expect(summariseUptime(pulses).uptimePct).toBe(95.8);
  });

  it("uses the median, so one timeout does not distort the figure", () => {
    // The mean of these is 1,290ms; the median is 150. A site that answers in
    // 150ms all day should not be shown as slow because one check timed out.
    const summary = summariseUptime([
      { reachable: true, responseTimeMs: 140 },
      { reachable: true, responseTimeMs: 150 },
      { reachable: true, responseTimeMs: 160 },
      { reachable: true, responseTimeMs: 10_000 },
      { reachable: true, responseTimeMs: 150 },
    ]);
    expect(summary.medianResponseMs).toBe(150);
  });

  it("averages the middle pair for an even count", () => {
    const summary = summariseUptime([
      { reachable: true, responseTimeMs: 100 },
      { reachable: true, responseTimeMs: 200 },
    ]);
    expect(summary.medianResponseMs).toBe(150);
  });

  it("excludes failed checks from the response time", () => {
    // A failed check's elapsed time is the timeout, not the site's speed.
    const summary = summariseUptime([
      { reachable: true, responseTimeMs: 100 },
      { reachable: false, responseTimeMs: 10_000 },
      { reachable: true, responseTimeMs: 120 },
    ]);
    expect(summary.medianResponseMs).toBe(110);
    expect(summary.uptimePct).toBe(66.7);
  });
});

describe("certDaysRemaining", () => {
  const now = new Date("2026-09-21T12:00:00.000Z");

  it("counts whole days to expiry", () => {
    expect(certDaysRemaining(new Date("2026-10-21T12:00:00.000Z"), now)).toBe(30);
  });

  it("returns a negative number for an already-expired certificate", () => {
    // Not clamped to zero: "expired 3 days ago" is the more useful fact, and
    // the alert thresholds treat anything at or below zero as past caring.
    expect(certDaysRemaining(new Date("2026-09-18T12:00:00.000Z"), now)).toBe(-3);
  });

  it("returns null for a missing or unparseable date", () => {
    expect(certDaysRemaining(null, now)).toBeNull();
    expect(certDaysRemaining(new Date("not a date"), now)).toBeNull();
  });
});

// ── The redirect path ─────────────────────────────────────────────────────────

/**
 * runPulse follows redirects by hand so every hop can be checked against the
 * SSRF guard first.
 *
 * `redirect: "follow"` would have quietly undone the check the URL passed when
 * the subscription was created: a target validated as public last month can
 * answer today with a 302 to a link-local metadata address, and fetch would
 * follow it before any of our code saw the Location header. Nothing about that
 * failure is visible in the dashboard, which is why it gets a test rather than
 * a comment.
 */
describe("runPulse — redirects (the real internet, httpbin.org)", () => {
  // httpbin.org is a public service made for testing HTTP clients. These tests skip when it cannot be reached.
  const ECHO = "https://httpbin.org";
  let online = false;
  const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];

  beforeAll(async () => {
    try { online = (await fetch(ECHO + "/status/200", { signal: AbortSignal.timeout(8_000) })).ok; } catch { online = false; }
  }, 15_000);

  // vitest.config.ts sets ALLOW_PRIVATE_SCAN_TARGETS=true for the whole suite, because almost every probe test drives the
  // scanner at a loopback server. With it on the guard correctly permits private addresses, so these tests would pass
  // whether the guard was called at all. Cleared here so the check is actually exercised.
  beforeEach(() => { delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"]; });
  afterEach(() => {
    if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
  });

  /** httpbin answers a 302 to `location`. */
  const redirectTo = (location: string) => ECHO + "/redirect-to?url=" + encodeURIComponent(location) + "&status_code=302";

  it("refuses to follow a redirect to a private address", async ({ skip }) => {
    if (!online) skip();
    const started = Date.now();
    const result = await runPulse(redirectTo("http://169.254.169.254/latest/meta-data/"));
    // The public first hop was fetched; the metadata address never was (it would have held the check for its full timeout).
    expect(result.reachable).toBe(false);
    expect(result.failureReason).toMatch(/^Blocked:/);
    expect(result.finalUrl).toContain("169.254.169.254");
    expect(Date.now() - started).toBeLessThan(8_000);
  }, 20_000);

  it("gives up rather than following a redirect chain forever", async ({ skip }) => {
    if (!online) skip();
    // httpbin answers this address with a chain of a thousand redirects; the check follows only a handful.
    const result = await runPulse(ECHO + "/redirect/1000");
    expect(result.reachable).toBe(false);
    expect(result.failureReason).toMatch(/redirects/);
  }, 40_000);

  it("records the final URL after a legitimate redirect, not the one asked for", async ({ skip }) => {
    if (!online) skip();
    // Monitored URLs redirect to www or to HTTPS constantly, so refusing redirects outright (the webhook module's approach)
    // would break the common case. The final URL is what drift compares against.
    const final = ECHO + "/response-headers?X-Frame-Options=DENY";
    const result = await runPulse(redirectTo(final));
    expect(result.reachable).toBe(true);
    expect(result.httpStatus).toBe(200);
    expect(result.finalUrl).toBe(final);
    expect(result.snapshot?.present).toContain("x-frame-options");
  }, 20_000);

  it("treats a 5xx as unreachable and a 404 as reachable", async ({ skip }) => {
    if (!online) skip();
    // Availability is "is the site serving", not "does this path exist".
    for (const [status, reachable] of [[503, false], [404, true], [200, true]] as const) {
      const result = await runPulse(ECHO + "/status/" + status);
      expect(result.reachable, "HTTP " + status).toBe(reachable);
    }
  }, 30_000);

  it("reports a name that does not exist as a result, never a throw", async () => {
    const result = await runPulse("http://no-such-host-" + Date.now() + ".invalid/");
    expect(result.reachable).toBe(false);
    expect(result.failureReason).toBeTruthy();
    expect(result.snapshot).toBeNull();
  });
});

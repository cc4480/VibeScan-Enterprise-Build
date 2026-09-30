import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
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
describe("runPulse — redirects", () => {
  const originalFetch = globalThis.fetch;
  const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];

  // vitest.config.ts sets ALLOW_PRIVATE_SCAN_TARGETS=true for the whole suite,
  // because almost every probe test drives the scanner at a loopback server.
  // That is the same switch a self-hosted operator sets, and with it on the
  // guard correctly permits private addresses — so these tests would pass
  // whether the guard was called at all. Cleared here, exactly as http.test.ts
  // does for its own redirect case, so the check is actually exercised.
  beforeEach(() => { delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"]; });

  afterEach(() => {
    if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // A public IP literal, and http rather than https, on purpose: an IP skips
  // the guard's DNS lookup and http skips the certificate handshake, so none of
  // these tests touch the network. The "legitimate redirect" case still has to
  // be a real redirect a monitored site would produce.
  /** A Response that redirects to `location`. */
  const redirectTo = (location: string, status = 302) =>
    new Response(null, { status, headers: { location } });

  it("refuses to follow a redirect to a private address", async () => {
    const requested: string[] = [];
    globalThis.fetch = vi.fn(async (input: Parameters<typeof fetch>[0]) => {
      requested.push(String(input));
      return redirectTo("http://169.254.169.254/latest/meta-data/");
    }) as typeof fetch;

    const result = await runPulse("http://93.184.216.34/");

    // The public first hop was fetched; the metadata address never was.
    expect(requested).toEqual(["http://93.184.216.34/"]);
    expect(result.reachable).toBe(false);
    expect(result.failureReason).toMatch(/^Blocked:/);
    expect(result.finalUrl).toContain("169.254.169.254");
  });

  it("gives up rather than looping forever on a redirect cycle", async () => {
    let calls = 0;
    globalThis.fetch = vi.fn(async () => {
      calls++;
      return redirectTo("http://93.184.216.34/loop");
    }) as typeof fetch;

    const result = await runPulse("http://93.184.216.34/");

    expect(result.reachable).toBe(false);
    expect(result.failureReason).toMatch(/redirects/);
    // Bounded: MAX_REDIRECTS + 1 requests, not an unbounded loop holding a
    // worker slot for the rest of the hour.
    expect(calls).toBeLessThanOrEqual(6);
  });

  it("records the final URL after a legitimate redirect, not the one asked for", async () => {
    // Monitored URLs redirect to www or to HTTPS constantly, so refusing
    // redirects outright — the webhook module's approach — would break the
    // common case. The final URL is what drift compares against.
    const responses: Record<string, Response> = {
      "http://93.184.216.34/": redirectTo("http://93.184.216.34/en/"),
      "http://93.184.216.34/en/": new Response("ok", {
        status: 200,
        headers: { "x-frame-options": "DENY" },
      }),
    };

    globalThis.fetch = vi.fn(async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      const res = responses[url];
      if (!res) throw new Error(`unexpected fetch: ${url}`);
      return res;
    }) as typeof fetch;

    const result = await runPulse("http://93.184.216.34/");

    expect(result.reachable).toBe(true);
    expect(result.httpStatus).toBe(200);
    expect(result.finalUrl).toBe("http://93.184.216.34/en/");
    expect(result.snapshot?.present).toEqual(["x-frame-options"]);
  });

  it("treats a 5xx as unreachable and a 404 as reachable", async () => {
    // Availability is "is the site serving", not "does this path exist".
    for (const [status, reachable] of [[503, false], [404, true], [200, true]] as const) {
      globalThis.fetch = vi.fn(async () => new Response(null, { status })) as typeof fetch;
      const result = await runPulse("http://93.184.216.34/");
      expect(result.reachable, `HTTP ${status}`).toBe(reachable);
    }
  });

  it("reports a network failure as a result, never a throw", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("getaddrinfo ENOTFOUND example.com");
    }) as typeof fetch;

    const result = await runPulse("http://93.184.216.34/");

    expect(result.reachable).toBe(false);
    expect(result.failureReason).toContain("ENOTFOUND");
    expect(result.snapshot).toBeNull();
  });
});

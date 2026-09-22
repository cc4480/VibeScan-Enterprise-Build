import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  runPulse,
  hstsBucket,
  snapshotHeaders,
  evaluateAvailability,
  evaluateDrift,
  summariseUptime,
  certDaysRemaining,
  DOWN_THRESHOLD,
} from "./monitorPulse";

/**
 * The hourly pulse decides, every hour, for every monitored site, whether to
 * send somebody an email. Both failure directions are silent in production:
 *
 *   - too eager, and it becomes the alert people mute — taking the real outage
 *     with it, which is the exact failure the per-kind preferences exist for;
 *   - too quiet, and a site is down all weekend with a dashboard saying
 *     "grade A".
 *
 * Nothing here touches a network or a database, because a decision this
 * consequential should not need either to be checked.
 */

describe("hstsBucket", () => {
  it("reads a year-long max-age as enforced", () => {
    expect(hstsBucket("max-age=31536000; includeSubDomains")).toBe("ok");
  });

  it("treats max-age=0 as OFF even though the header is present", () => {
    // The case presence-checking alone cannot see. A site that ships
    // Strict-Transport-Security: max-age=0 has disabled HSTS while looking
    // untouched to anything comparing header names.
    expect(hstsBucket("max-age=0")).toBe("none");
  });

  it("flags a max-age under a week as short", () => {
    expect(hstsBucket("max-age=3600")).toBe("short");
  });

  it("is case- and whitespace-insensitive, and reads a quoted value", () => {
    expect(hstsBucket('MAX-AGE = "31536000"')).toBe("ok");
  });

  it("treats a missing or malformed header as none", () => {
    expect(hstsBucket(null)).toBe("none");
    expect(hstsBucket(undefined)).toBe("none");
    expect(hstsBucket("")).toBe("none");
    expect(hstsBucket("includeSubDomains")).toBe("none");
  });
});

describe("snapshotHeaders", () => {
  it("records which tracked headers are present", () => {
    const snap = snapshotHeaders({
      "Strict-Transport-Security": "max-age=31536000",
      "X-Frame-Options": "DENY",
      "Server": "nginx",
    });

    expect(snap.present).toEqual(["strict-transport-security", "x-frame-options"]);
    expect(snap.hsts).toBe("ok");
  });

  it("ignores an empty header value", () => {
    const snap = snapshotHeaders({ "X-Frame-Options": "" });
    expect(snap.present).toEqual([]);
  });

  it("gives the SAME fingerprint when a CSP nonce changes", () => {
    // The property that makes hourly checks usable at all. A per-response nonce
    // is different on every single request, so fingerprinting header VALUES
    // would report drift every hour on precisely the sites doing CSP properly —
    // and a site owner who gets a false "your CSP changed" every hour turns
    // the alert off, including the day it is true.
    const first = snapshotHeaders({
      "Content-Security-Policy": "script-src 'nonce-aaaaaaaaaaaa'",
    });
    const second = snapshotHeaders({
      "Content-Security-Policy": "script-src 'nonce-bbbbbbbbbbbb'",
    });

    expect(second.fingerprint).toBe(first.fingerprint);
  });

  it("changes the fingerprint when a header goes away", () => {
    const before = snapshotHeaders({ "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer" });
    const after = snapshotHeaders({ "X-Frame-Options": "DENY" });
    expect(after.fingerprint).not.toBe(before.fingerprint);
  });

  it("changes the fingerprint when HSTS is switched off but left in place", () => {
    const before = snapshotHeaders({ "Strict-Transport-Security": "max-age=31536000" });
    const after = snapshotHeaders({ "Strict-Transport-Security": "max-age=0" });

    // Same header name present in both, so anything comparing names alone would
    // call these identical.
    expect(after.present).toEqual(before.present);
    expect(after.fingerprint).not.toBe(before.fingerprint);
  });

  it("reads a Headers object and a plain record identically", () => {
    const viaHeaders = snapshotHeaders(
      new Headers({ "strict-transport-security": "max-age=31536000", "x-frame-options": "DENY" }),
    );
    const viaRecord = snapshotHeaders({
      "Strict-Transport-Security": "max-age=31536000",
      "X-Frame-Options": "DENY",
    });

    expect(viaHeaders.fingerprint).toBe(viaRecord.fingerprint);
  });

  it("does not depend on the order headers arrive in", () => {
    const a = snapshotHeaders({ "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer" });
    const b = snapshotHeaders({ "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY" });
    expect(a.fingerprint).toBe(b.fingerprint);
  });
});

describe("evaluateAvailability", () => {
  const up = { reachable: true };
  const down = { reachable: false };

  it("stays silent on the first failure", () => {
    // A single dropped request at 03:00 is not an outage.
    expect(evaluateAvailability([up, up, up], down)).toBeNull();
  });

  it("alerts once the failures reach the threshold", () => {
    expect(evaluateAvailability([down, up, up], down)).toBe("down");
    expect(DOWN_THRESHOLD).toBe(2);
  });

  it("does NOT alert again while the site stays down", () => {
    // A four-hour outage sends one email, not four. This is the difference
    // between an alert someone reads and an alert someone filters.
    expect(evaluateAvailability([down, down, up], down)).toBeNull();
    expect(evaluateAvailability([down, down, down, down], down)).toBeNull();
  });

  it("reports a recovery after a confirmed outage", () => {
    expect(evaluateAvailability([down, down, up], up)).toBe("recovered");
  });

  it("does NOT report a recovery from a blip nobody was told about", () => {
    // Symmetry that matters: if the "down" was never sent, a "recovered" is an
    // email about an event the reader never heard of.
    expect(evaluateAvailability([down, up, up], up)).toBeNull();
  });

  it("stays silent when the site was up and stays up", () => {
    expect(evaluateAvailability([up, up, up], up)).toBeNull();
  });

  it("handles a subscription with no history at all", () => {
    // The very first pulse. One failure is not yet an outage.
    expect(evaluateAvailability([], down)).toBeNull();
    expect(evaluateAvailability([], up)).toBeNull();
  });

  it("sends at most one alert per outage across a whole run of checks", () => {
    // Replays twelve hourly checks and counts the emails. Written as a
    // simulation because the per-call assertions above can all pass while the
    // sequence still produces a storm.
    const observations = [
      true, true, false, false, false, false, true, true, false, true, true, true,
    ];

    const events: string[] = [];
    const history: Array<{ reachable: boolean }> = [];

    for (const reachable of observations) {
      const event = evaluateAvailability([...history].reverse(), { reachable });
      if (event) events.push(event);
      history.push({ reachable });
    }

    // One real outage (four consecutive failures) and one single-check blip.
    expect(events).toEqual(["down", "recovered"]);
  });
});

describe("evaluateDrift", () => {
  const snapshotOf = (headers: Record<string, string>) => snapshotHeaders(headers);

  it("reports nothing when there is no previous pulse to compare against", () => {
    const snapshot = snapshotOf({ "X-Frame-Options": "DENY" });
    expect(evaluateDrift(null, { snapshot, finalUrl: "https://example.com/" })).toEqual([]);
  });

  it("reports nothing when the fingerprint is unchanged", () => {
    const snapshot = snapshotOf({ "X-Frame-Options": "DENY" });
    const previous = {
      headerFingerprint: snapshot.fingerprint,
      presentHeaders: snapshot.present,
      finalUrl: "https://example.com/",
    };
    expect(evaluateDrift(previous, { snapshot, finalUrl: "https://example.com/" })).toEqual([]);
  });

  it("reports a removed security header", () => {
    const before = snapshotOf({ "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer" });
    const after = snapshotOf({ "X-Frame-Options": "DENY" });

    const findings = evaluateDrift(
      { headerFingerprint: before.fingerprint, presentHeaders: before.present, finalUrl: "https://example.com/" },
      { snapshot: after, finalUrl: "https://example.com/" },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ kind: "header_removed", detail: "referrer-policy", severity: "medium" });
  });

  it("stays SILENT when a header is added", () => {
    // Good news is not an alert. A deploy that adds a CSP should not email
    // anybody, or the alert stops meaning "something got worse".
    const before = snapshotOf({ "X-Frame-Options": "DENY" });
    const after = snapshotOf({ "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'" });

    const findings = evaluateDrift(
      { headerFingerprint: before.fingerprint, presentHeaders: before.present, finalUrl: "https://example.com/" },
      { snapshot: after, finalUrl: "https://example.com/" },
    );

    expect(findings).toEqual([]);
  });

  it("reports HSTS being switched off while the header stays present", () => {
    const before = snapshotOf({ "Strict-Transport-Security": "max-age=31536000" });
    const after = snapshotOf({ "Strict-Transport-Security": "max-age=0" });

    const findings = evaluateDrift(
      { headerFingerprint: before.fingerprint, presentHeaders: before.present, finalUrl: "https://example.com/" },
      { snapshot: after, finalUrl: "https://example.com/" },
      before.hsts,
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("hsts_weakened");
    expect(findings[0].severity).toBe("high");
  });

  it("reports a changed redirect host", () => {
    const before = snapshotOf({ "X-Frame-Options": "DENY" });
    const after = snapshotOf({});

    const findings = evaluateDrift(
      { headerFingerprint: before.fingerprint, presentHeaders: before.present, finalUrl: "https://example.com/" },
      { snapshot: after, finalUrl: "https://someone-elses-domain.test/" },
    );

    const hostChange = findings.find((f) => f.kind === "final_url_changed");
    expect(hostChange).toBeDefined();
    expect(hostChange?.severity).toBe("high");
    expect(hostChange?.detail).toContain("someone-elses-domain.test");
  });

  it("stays silent on a path-only change to the same host", () => {
    // Routine. Sites move their landing page.
    const snapshot = snapshotOf({ "X-Frame-Options": "DENY" });
    const findings = evaluateDrift(
      { headerFingerprint: "a-different-fingerprint", presentHeaders: snapshot.present, finalUrl: "https://example.com/home" },
      { snapshot, finalUrl: "https://example.com/welcome" },
    );
    expect(findings).toEqual([]);
  });

  it("treats an HTTPS-to-HTTP downgrade as critical", () => {
    const before = snapshotOf({ "Strict-Transport-Security": "max-age=31536000" });
    const after = snapshotOf({});

    const findings = evaluateDrift(
      { headerFingerprint: before.fingerprint, presentHeaders: before.present, finalUrl: "https://example.com/" },
      { snapshot: after, finalUrl: "http://example.com/" },
      before.hsts,
    );

    const downgrade = findings.find((f) => f.kind === "tls_downgrade");
    expect(downgrade).toBeDefined();
    expect(downgrade?.severity).toBe("critical");
    // The host is unchanged, so it must not ALSO be reported as a host change.
    expect(findings.some((f) => f.kind === "final_url_changed")).toBe(false);
  });
});

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

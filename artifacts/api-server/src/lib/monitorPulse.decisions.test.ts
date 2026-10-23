import { describe, it, expect } from "vitest";
import { snapshotHeaders, evaluateAvailability, evaluateDrift, DOWN_THRESHOLD } from "./monitorPulse";

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

import { describe, it, expect } from "vitest";
import {
  shouldNotify,
  defaultPrefs,
  normaliseSeverity,
  inQuietHours,
  isValidTimezone,
  type NotificationPrefs,
  type AlertKind,
} from "./notificationPrefs";

/**
 * This decides whether somebody hears that their certificate expires in seven
 * days. It fails quietly in both directions — an alert that should have been
 * sent and wasn't looks identical to a quiet week.
 */

const prefs = (over: Partial<NotificationPrefs> = {}): NotificationPrefs => ({
  ...defaultPrefs(),
  ...over,
});

describe("shouldNotify — defaults reproduce today's behaviour", () => {
  const kinds: AlertKind[] = ["cve", "regression", "cert_expiry", "scan_complete"];

  it("delivers every alert kind on both channels out of the box", () => {
    // The property that matters on the day this ships: existing users must
    // notice no change until they choose one.
    for (const kind of kinds) {
      for (const channel of ["email", "webhook"] as const) {
        expect(shouldNotify(prefs(), { kind, channel, severity: "info" }), `${kind}/${channel}`)
          .toBe(true);
      }
    }
  });
});

describe("shouldNotify — the email master switch", () => {
  it("silences email when the user unsubscribed", () => {
    expect(shouldNotify(prefs({ emailOptedOut: true }), { kind: "cve", channel: "email" }))
      .toBe(false);
  });

  it("does NOT silence webhooks", () => {
    // alertEmailsOptedOut is what one-click List-Unsubscribe toggles. Someone
    // who silenced their inbox has not asked us to stop posting to their
    // team's Slack, and conflating the two would quietly break integrations
    // the moment anyone hits unsubscribe in Gmail.
    expect(shouldNotify(prefs({ emailOptedOut: true }), { kind: "cve", channel: "webhook" }))
      .toBe(true);
  });
});

describe("shouldNotify — per-kind opt-out", () => {
  it("silences only the kind that was turned off", () => {
    const p = prefs({ optedOutKinds: new Set<AlertKind>(["scan_complete"]) });
    expect(shouldNotify(p, { kind: "scan_complete", channel: "email" })).toBe(false);
    expect(shouldNotify(p, { kind: "cve", channel: "email" })).toBe(true);
    expect(shouldNotify(p, { kind: "cert_expiry", channel: "email" })).toBe(true);
  });

  it("applies to webhooks as well as email", () => {
    const p = prefs({ optedOutKinds: new Set<AlertKind>(["regression"]) });
    expect(shouldNotify(p, { kind: "regression", channel: "webhook" })).toBe(false);
  });
});

describe("shouldNotify — severity floor", () => {
  it("drops alerts below the floor and keeps the rest", () => {
    const p = prefs({ minSeverity: "high" });
    expect(shouldNotify(p, { kind: "cve", channel: "email", severity: "low" })).toBe(false);
    expect(shouldNotify(p, { kind: "cve", channel: "email", severity: "medium" })).toBe(false);
    expect(shouldNotify(p, { kind: "cve", channel: "email", severity: "high" })).toBe(true);
    expect(shouldNotify(p, { kind: "cve", channel: "email", severity: "critical" })).toBe(true);
  });

  it("matches severity case-insensitively", () => {
    // NVD sends "CRITICAL"; scan findings are lowercase. A floor that only
    // understood one of them would silently drop half the alerts.
    const p = prefs({ minSeverity: "high" });
    expect(shouldNotify(p, { kind: "cve", channel: "email", severity: "CRITICAL" })).toBe(true);
    expect(shouldNotify(p, { kind: "cve", channel: "email", severity: "LOW" })).toBe(false);
  });

  it("NEVER hides a severity-less alert behind the floor", () => {
    // cert_expiry carries days-remaining, not a severity. Treating that
    // absence as "info" would hide expiry warnings from everyone who raised
    // their floor — the single worst outcome this whole feature could produce.
    const p = prefs({ minSeverity: "critical" });
    expect(shouldNotify(p, { kind: "cert_expiry", channel: "email" })).toBe(true);
    expect(shouldNotify(p, { kind: "cert_expiry", channel: "email", severity: null })).toBe(true);
    expect(shouldNotify(p, { kind: "scan_complete", channel: "email", severity: "" })).toBe(true);
  });

  it("delivers an unreadable severity rather than dropping it", () => {
    // Fail loud, not silent: a severity string we do not recognise is not a
    // reason to withhold a security alert.
    const p = prefs({ minSeverity: "critical" });
    expect(shouldNotify(p, { kind: "cve", channel: "email", severity: "SEV-9" })).toBe(true);
  });
});

describe("normaliseSeverity", () => {
  it("lowercases known values and treats unknown ones as critical", () => {
    expect(normaliseSeverity("HIGH")).toBe("high");
    expect(normaliseSeverity("medium")).toBe("medium");
    expect(normaliseSeverity("banana")).toBe("critical");
    expect(normaliseSeverity(null)).toBe("critical");
    expect(normaliseSeverity(undefined)).toBe("critical");
  });
});

describe("quiet hours", () => {
  // 03:00 UTC is 04:00 in London (a January date, so London is on GMT).
  const night = new Date("2026-01-15T03:00:00Z");
  const noon = new Date("2026-01-15T12:00:00Z");
  const overnight = { start: 22, end: 7, timezone: "UTC" };

  it("a window that wraps midnight covers late evening and early morning, not the day", () => {
    expect(inQuietHours(overnight, new Date("2026-01-15T23:30:00Z"))).toBe(true);
    expect(inQuietHours(overnight, night)).toBe(true);
    expect(inQuietHours(overnight, noon)).toBe(false);
  });

  it("start is inclusive and end is exclusive", () => {
    expect(inQuietHours(overnight, new Date("2026-01-15T22:00:00Z"))).toBe(true);
    expect(inQuietHours(overnight, new Date("2026-01-15T07:00:00Z"))).toBe(false);
    expect(inQuietHours(overnight, new Date("2026-01-15T06:59:00Z"))).toBe(true);
  });

  it("reads the hour in the person's own time zone", () => {
    // 03:00 UTC is 22:00 the evening before in New York (EST), which is inside 22-7.
    expect(inQuietHours({ ...overnight, timezone: "America/New_York" }, night)).toBe(true);
    // 12:00 UTC is 21:00 in Tokyo, just before the window.
    expect(inQuietHours({ ...overnight, timezone: "Asia/Tokyo" }, noon)).toBe(false);
    expect(inQuietHours({ start: 9, end: 17, timezone: "Asia/Tokyo" }, night)).toBe(true); // 12:00 in Tokyo
  });

  it("a same-day window works, and none, an empty window or a bad zone is never quiet", () => {
    expect(inQuietHours({ start: 9, end: 17, timezone: "UTC" }, noon)).toBe(true);
    expect(inQuietHours({ start: 9, end: 17, timezone: "UTC" }, night)).toBe(false);
    expect(inQuietHours(null, night)).toBe(false);
    expect(inQuietHours({ start: 5, end: 5, timezone: "UTC" }, night)).toBe(false);
    expect(inQuietHours({ start: 0, end: 23, timezone: "Not/AZone" }, night)).toBe(false);
  });

  it("validates zone names", () => {
    expect(isValidTimezone("Europe/London")).toBe(true);
    expect(isValidTimezone("Not/AZone")).toBe(false);
    expect(isValidTimezone("")).toBe(false);
  });

  it("holds back what can wait, on both channels, and lets through what cannot", () => {
    const p = prefs({ quietHours: overnight });
    for (const channel of ["email", "webhook"] as const) {
      expect(shouldNotify(p, { kind: "scan_complete", channel, now: night })).toBe(false);
      expect(shouldNotify(p, { kind: "cve", channel, severity: "high", now: night })).toBe(false);
      expect(shouldNotify(p, { kind: "regression", channel, severity: "medium", now: night })).toBe(false);
      expect(shouldNotify(p, { kind: "drift", channel, severity: "low", now: night })).toBe(false);
      // Cannot wait: a critical finding, an expiring certificate (sent once), an outage.
      expect(shouldNotify(p, { kind: "cve", channel, severity: "CRITICAL", now: night })).toBe(true);
      expect(shouldNotify(p, { kind: "cert_expiry", channel, now: night })).toBe(true);
      expect(shouldNotify(p, { kind: "availability", channel, now: night })).toBe(true);
    }
  });

  it("changes nothing outside the window, or without quiet hours", () => {
    expect(shouldNotify(prefs({ quietHours: overnight }), { kind: "scan_complete", channel: "email", now: noon })).toBe(true);
    expect(shouldNotify(prefs(), { kind: "scan_complete", channel: "email", now: night })).toBe(true);
  });

  it("does not override the other preferences", () => {
    const p = prefs({ quietHours: overnight, optedOutKinds: new Set<AlertKind>(["cert_expiry"]) });
    expect(shouldNotify(p, { kind: "cert_expiry", channel: "email", now: night })).toBe(false);
  });
});

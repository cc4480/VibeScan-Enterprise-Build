import { describe, it, expect } from "vitest";
import {
  shouldNotify,
  defaultPrefs,
  normaliseSeverity,
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

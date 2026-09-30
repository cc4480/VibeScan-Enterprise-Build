import { describe, it, expect } from "vitest";
import { hstsBucket, snapshotHeaders } from "./monitorPulse";

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

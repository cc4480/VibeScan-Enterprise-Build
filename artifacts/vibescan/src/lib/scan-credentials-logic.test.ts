import { describe, it, expect } from "vitest";
import {
  credentialsReady,
  credentialsTouched,
  secondAccountReady,
  autoAccountRequested,
  emptyCredentials,
  emptySecondAccount,
} from "@/components/scan-credentials-fields";

/**
 * These predicates decide whether credentials are sent at all. Getting them
 * wrong either silently downgrades a credentialed scan to an anonymous one, or
 * sends a half-filled form the server will reject.
 */

describe("credentialsReady", () => {
  it("is false for an untouched form", () => {
    expect(credentialsReady(emptyCredentials)).toBe(false);
  });

  it("requires the authorisation attestation even when complete", () => {
    // The server enforces this too; the point is not to send a request that is
    // certain to be refused.
    expect(
      credentialsReady({ ...emptyCredentials, cookie: "sid=abc", authorized: false }),
    ).toBe(false);
  });

  it("accepts a cookie or a bearer token in session mode", () => {
    expect(credentialsReady({ ...emptyCredentials, authorized: true, cookie: "sid=abc" })).toBe(true);
    expect(credentialsReady({ ...emptyCredentials, authorized: true, bearerToken: "tok" })).toBe(true);
  });

  it("ignores whitespace-only input", () => {
    expect(credentialsReady({ ...emptyCredentials, authorized: true, cookie: "   " })).toBe(false);
  });

  it("requires all three fields in form mode", () => {
    const base = { ...emptyCredentials, mode: "form" as const, authorized: true };
    expect(credentialsReady({ ...base, loginUrl: "https://a/login" })).toBe(false);
    expect(credentialsReady({ ...base, loginUrl: "https://a/login", username: "u" })).toBe(false);
    expect(
      credentialsReady({ ...base, loginUrl: "https://a/login", username: "u", password: "p" }),
    ).toBe(true);
  });

  it("does not accept session fields as a substitute in form mode", () => {
    expect(
      credentialsReady({ ...emptyCredentials, mode: "form", authorized: true, cookie: "sid=abc" }),
    ).toBe(false);
  });
});

describe("credentialsTouched", () => {
  it("is false until something is entered", () => {
    expect(credentialsTouched(emptyCredentials)).toBe(false);
  });

  it("notices any single field, including the checkbox alone", () => {
    expect(credentialsTouched({ ...emptyCredentials, authorized: true })).toBe(true);
    expect(credentialsTouched({ ...emptyCredentials, username: "u" })).toBe(true);
    expect(credentialsTouched({ ...emptyCredentials, password: "p" })).toBe(true);
  });
});

describe("secondAccountReady", () => {
  it("needs the checkbox and a session of its own", () => {
    expect(secondAccountReady(emptySecondAccount)).toBe(false);
    expect(secondAccountReady({ ...emptySecondAccount, enabled: true })).toBe(false);
    expect(secondAccountReady({ ...emptySecondAccount, cookie: "sid=other" })).toBe(false);
    expect(
      secondAccountReady({ ...emptySecondAccount, enabled: true, cookie: "sid=other" }),
    ).toBe(true);
  });
});

import { secondCredentialsPayload, secondLoginUrl } from "@/components/second-account";

describe("second account signing in with a form", () => {
  const primaryForm = { ...emptyCredentials, mode: "form" as const, loginUrl: "https://app.example.com/login", username: "a", password: "x", authorized: true };
  const second = { ...emptySecondAccount, enabled: true, mode: "form" as const, username: "bob", password: "pw" };

  it("reuses the first account's sign-in page, so only a username and password are needed", () => {
    expect(secondAccountReady(second, primaryForm)).toBe(true);
    expect(secondLoginUrl(second, primaryForm)).toBe("https://app.example.com/login");
    expect(secondCredentialsPayload(second, primaryForm)).toEqual({
      mode: "form", authorized: true, loginUrl: "https://app.example.com/login", username: "bob", password: "pw",
    });
  });

  it("prefers a sign-in page given for the second account", () => {
    const own = { ...second, loginUrl: "https://other.example.com/login" };
    expect(secondLoginUrl(own, primaryForm)).toBe("https://other.example.com/login");
  });

  it("is not ready without a page to sign in at, a username or a password", () => {
    expect(secondAccountReady(second)).toBe(false);
    expect(secondAccountReady(second, { ...emptyCredentials, mode: "session", cookie: "s=1" })).toBe(false);
    expect(secondAccountReady({ ...second, username: " " }, primaryForm)).toBe(false);
    expect(secondAccountReady({ ...second, password: "" }, primaryForm)).toBe(false);
  });

  it("only counts when the checkbox is on", () => {
    expect(secondAccountReady({ ...second, enabled: false }, primaryForm)).toBe(false);
  });

  it("session mode still sends only the cookie and token", () => {
    const s = { ...emptySecondAccount, enabled: true, cookie: " sid=other ", bearerToken: "" };
    expect(secondCredentialsPayload(s)).toEqual({ mode: "session", authorized: true, cookie: "sid=other", bearerToken: null });
  });
});

describe("letting the scan create the second account", () => {
  it("is off in a fresh form, and off when the second-account box is unticked even if chosen before", () => {
    expect(autoAccountRequested(emptySecondAccount)).toBe(false);
    expect(autoAccountRequested({ ...emptySecondAccount, autoCreate: true })).toBe(false);
  });

  it("is requested only when the box is ticked and the option chosen", () => {
    expect(autoAccountRequested({ ...emptySecondAccount, enabled: true, autoCreate: true })).toBe(true);
    expect(autoAccountRequested({ ...emptySecondAccount, enabled: true })).toBe(false);
  });

  it("never counts as a supplied second account, so no credentials are sent for it", () => {
    // Stale text left in the fields from an earlier choice must not be sent as a login.
    expect(secondAccountReady({ ...emptySecondAccount, enabled: true, autoCreate: true, cookie: "sid=stale" })).toBe(false);
  });
});

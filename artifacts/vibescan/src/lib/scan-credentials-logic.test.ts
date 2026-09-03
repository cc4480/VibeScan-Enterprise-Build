import { describe, it, expect } from "vitest";
import {
  credentialsReady,
  credentialsTouched,
  secondAccountReady,
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

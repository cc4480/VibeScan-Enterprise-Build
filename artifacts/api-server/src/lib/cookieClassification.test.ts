import { describe, it, expect } from "vitest";
import {
  isLikelySessionCookie,
  isCsrfTokenCookie,
  requiresHttpOnly,
} from "./cookieClassification.js";

describe("session cookie classification", () => {
  it("recognises the usual session and auth names", () => {
    for (const n of ["sessionid", "PHPSESSID", "JSESSIONID", "connect.sid", "auth_token", "jwt", "remember_me", "sid"]) {
      expect(isLikelySessionCookie(n), n).toBe(true);
    }
  });

  it("leaves UI-state and analytics cookies alone", () => {
    for (const n of ["theme", "locale", "_ga", "sidebar_collapsed", "consent"]) {
      expect(isLikelySessionCookie(n), n).toBe(false);
    }
  });
});

describe("a CSRF token must stay readable by JavaScript", () => {
  // Dropbox sets __Host-js_csrf as Secure, SameSite=None and deliberately NOT
  // HttpOnly, while every other cookie it sets carries HttpOnly. We reported
  // that correct implementation as "Session Cookie Missing HttpOnly Flag".
  it("does not require HttpOnly on a double-submit CSRF token", () => {
    for (const n of ["__Host-js_csrf", "csrftoken", "XSRF-TOKEN", "_csrf"]) {
      expect(isCsrfTokenCookie(n), n).toBe(true);
      expect(requiresHttpOnly(n), n).toBe(false);
    }
  });

  it("still treats it as a session cookie for Secure and SameSite", () => {
    // The exemption is for HttpOnly alone — a CSRF token sent over plaintext
    // or attached cross-site is still a real problem.
    expect(isLikelySessionCookie("__Host-js_csrf")).toBe(true);
    expect(isLikelySessionCookie("XSRF-TOKEN")).toBe(true);
  });

  it("does not exempt a name that is also a session cookie", () => {
    // Ambiguous names get the safer reading: keep it locked down.
    for (const n of ["session_csrf_token", "csrf_jsessionid", "auth_token_csrf"]) {
      expect(isCsrfTokenCookie(n), n).toBe(false);
      expect(requiresHttpOnly(n), n).toBe(true);
    }
  });

  it("requires HttpOnly on everything else", () => {
    for (const n of ["sessionid", "auth_token", "theme", "_ga"]) {
      expect(requiresHttpOnly(n), n).toBe(true);
    }
  });
});

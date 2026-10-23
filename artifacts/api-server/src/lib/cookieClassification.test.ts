import { describe, it, expect } from "vitest";
import {
  isLikelySessionCookie,
  isCsrfTokenCookie,
  requiresHttpOnly,
  isClientPreferenceCookie,
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

describe("analytics identifiers are not session cookies", () => {
  it("does not treat a vendor script's session or token id as a login", () => {
    for (const n of ["ajs_session_id", "ajs_anonymous_id", "_hjSession_123456", "_hjSessionUser_123456", "mp_abc_mixpanel", "amplitude_id_x", "ph_phc_abc_posthog", "_ga_ABC123", "_pk_ses.1.abcd"]) {
      expect(isLikelySessionCookie(n), n).toBe(false);
    }
  });

  it("still treats a real session cookie as one, including one that merely contains an analytics-looking word", () => {
    for (const n of ["session_id", "my_ajs_session", "sessionid", "auth_token", "_session_id", "ph_session"]) {
      expect(isLikelySessionCookie(n), n).toBe(true);
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
    for (const n of ["sessionid", "auth_token", "prefs", "_ga"]) {
      expect(requiresHttpOnly(n), n).toBe(true);
    }
  });
});

describe("isClientPreferenceCookie", () => {
  it.each(["lang", "NEXT_LOCALE", "locale", "pll_language", "site-lang", "theme", "color_scheme", "timezone", "cookieconsent_status", "OptanonConsent", "cc_cookie"])(
    "%s is meant to be read by the page, so HttpOnly is not required",
    (name) => {
      expect(isClientPreferenceCookie(name)).toBe(true);
      expect(requiresHttpOnly(name)).toBe(false);
    },
  );

  it.each(["session_lang", "auth_locale_token", "language_session", "uid", "prefs", "_ga", "language-pack"])(
    "%s still needs HttpOnly",
    (name) => {
      expect(isClientPreferenceCookie(name)).toBe(false);
    },
  );
});

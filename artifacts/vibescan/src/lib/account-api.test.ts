import { describe, it, expect } from "vitest";
import { accountErrorMessage } from "./account-api.js";

/**
 * Error text shown on the account screens.
 *
 * The server writes these strings for people — "Use at least 10 characters",
 * "Email or password is incorrect" — so the job here is to surface them rather
 * than replace them with something vaguer, and to fall back cleanly when the
 * failure has no message worth showing.
 */
describe("accountErrorMessage", () => {
  it("prefers the server's own message", () => {
    const err = { data: { error: "Use at least 10 characters" } };
    expect(accountErrorMessage(err, "fallback")).toBe("Use at least 10 characters");
  });

  it("falls back when the shape is not an API error", () => {
    expect(accountErrorMessage(new Error("socket hang up"), "Could not sign you in")).toBe(
      "Could not sign you in",
    );
    expect(accountErrorMessage(null, "fallback")).toBe("fallback");
    expect(accountErrorMessage(undefined, "fallback")).toBe("fallback");
    expect(accountErrorMessage("a string", "fallback")).toBe("fallback");
  });

  it("falls back when the error field is empty or not a string", () => {
    // An empty message is worse than the fallback: it would render a blank
    // error box that says nothing went wrong.
    expect(accountErrorMessage({ data: { error: "" } }, "fallback")).toBe("fallback");
    expect(accountErrorMessage({ data: { error: "   " } }, "fallback")).toBe("fallback");
    expect(accountErrorMessage({ data: { error: 42 } }, "fallback")).toBe("fallback");
    expect(accountErrorMessage({ data: {} }, "fallback")).toBe("fallback");
    expect(accountErrorMessage({ data: null }, "fallback")).toBe("fallback");
  });
});

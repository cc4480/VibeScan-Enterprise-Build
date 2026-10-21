import { describe, it, expect, vi } from "vitest";
import { tokenInUrl, clearTokenFromUrl } from "./url-token";

/** A stand-in for the browser window: the address and a replaceState that records what it was given. */
function fakeWindow(href: string) {
  const replaceState = vi.fn((_state: unknown, _unused: string, url?: string | URL | null) => {
    const next = new URL(String(url), "https://secscan.us");
    win.location.href = `https://secscan.us${next.pathname}${next.search}${next.hash}`;
  });
  const win = { location: { href }, history: { state: null, replaceState } };
  return win;
}

describe("tokenInUrl", () => {
  it("reads the token and leaves the address alone", () => {
    const win = fakeWindow("https://secscan.us/verify-email?token=abc123&x=1");
    expect(tokenInUrl(win)).toBe("abc123");
    expect(win.history.replaceState).not.toHaveBeenCalled();
  });

  it("returns an empty string when there is no token", () => {
    expect(tokenInUrl(fakeWindow("https://secscan.us/reset-password"))).toBe("");
    expect(tokenInUrl(undefined)).toBe("");
  });
});

describe("clearTokenFromUrl", () => {
  it("removes the token from the address bar with replaceState, keeping other parameters and the hash", () => {
    const win = fakeWindow("https://secscan.us/reset-password?token=abc123&ref=mail#top");
    clearTokenFromUrl(win);
    expect(win.history.replaceState).toHaveBeenCalledTimes(1);
    expect(win.history.replaceState).toHaveBeenCalledWith(null, "", "/reset-password?ref=mail#top");
    expect(win.location.href).not.toContain("token");
  });

  it("is a no-op, with no history call, when there is no token", () => {
    const win = fakeWindow("https://secscan.us/reset-password?ref=mail");
    clearTokenFromUrl(win);
    expect(win.history.replaceState).not.toHaveBeenCalled();
  });

  it("does nothing the second time, so a React double-mount is harmless", () => {
    const win = fakeWindow("https://secscan.us/verify-email?token=abc123");
    clearTokenFromUrl(win);
    clearTokenFromUrl(win);
    expect(win.history.replaceState).toHaveBeenCalledTimes(1);
  });
});

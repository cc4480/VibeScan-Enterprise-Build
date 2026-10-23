import { describe, it, expect } from "vitest";
import { toSetCookieStrings, type BrowserCookie } from "./browser.js";

describe("toSetCookieStrings — only the scanned site's own cookies", () => {
  const target = "https://www.bestbuy.com/";

  it("drops third-party cookies the page happened to load", () => {
    // The real false positive: a Playwright context accumulates cookies from
    // every origin the page touches. bestbuy.com sends no Set-Cookie at all,
    // yet was reported as having a session cookie "SID" without Secure — SID
    // is Google's.
    const cookies: BrowserCookie[] = [
      { name: "SID", value: "abc", domain: ".google.com" },
      { name: "_fbp", value: "x", domain: ".facebook.com" },
      { name: "uuid2", value: "y", domain: ".adnxs.com" },
    ];
    expect(toSetCookieStrings(cookies, target)).toEqual([]);
  });

  it("keeps the site's own cookies, including parent-domain ones", () => {
    const cookies: BrowserCookie[] = [
      { name: "sess", value: "1", domain: "www.bestbuy.com", secure: true, httpOnly: true },
      { name: "pref", value: "2", domain: ".bestbuy.com" },
      { name: "SID", value: "3", domain: ".google.com" },
    ];
    const out = toSetCookieStrings(cookies, target);
    expect(out).toHaveLength(2);
    expect(out[0]).toBe("sess=1; Secure; HttpOnly");
    expect(out[1]).toBe("pref=2");
  });

  it("keeps host-only cookies that report no domain", () => {
    const out = toSetCookieStrings([{ name: "a", value: "b" }], target);
    expect(out).toEqual(["a=b"]);
  });

  it("does not treat a lookalike domain as first-party", () => {
    // notbestbuy.com must not match bestbuy.com
    const out = toSetCookieStrings([{ name: "x", value: "1", domain: "notbestbuy.com" }], target);
    expect(out).toEqual([]);
  });

  it("serialises flags the analyzer depends on", () => {
    const out = toSetCookieStrings(
      [{ name: "s", value: "v", domain: ".bestbuy.com", secure: true, httpOnly: true, sameSite: "Lax", path: "/" }],
      target,
    );
    expect(out[0]).toBe("s=v; Secure; HttpOnly; SameSite=Lax; Path=/");
  });
});

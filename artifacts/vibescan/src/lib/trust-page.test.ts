import { describe, it, expect } from "vitest";
import { accentOrNull, coverageLine, findingsLine, freshness, heading } from "./trust-page";

const NOW = new Date("2026-10-23T12:00:00Z");

describe("accentOrNull", () => {
  it("uses only a lower-case #rrggbb", () => {
    expect(accentOrNull("#1a73e8")).toBe("#1a73e8");
    for (const v of [null, undefined, "", "#1A73E8", "red", "#fff", "#12345g", "#1a73e8; background:url(x)", 'javascript:alert(1)']) {
      expect(accentOrNull(v as string | null | undefined), String(v)).toBeNull();
    }
  });
});

describe("freshness", () => {
  it("says when a current scan was made", () => {
    expect(freshness("2026-10-23T08:00:00Z", false, NOW)).toEqual({ text: "Scanned today.", warn: false });
    expect(freshness("2026-10-22T08:00:00Z", false, NOW)).toEqual({ text: "Scanned yesterday.", warn: false });
    expect(freshness("2026-10-18T12:00:00Z", false, NOW)).toEqual({ text: "Scanned 5 days ago.", warn: false });
  });
  it("says plainly that a stale scan is out of date, and still says how old", () => {
    const f = freshness("2026-08-01T12:00:00Z", true, NOW);
    expect(f.warn).toBe(true);
    expect(f.text).toContain("83 days ago");
    expect(f.text).toContain("out of date");
  });
  it("never reports a negative age for a scan dated in the future", () => {
    expect(freshness("2026-10-25T12:00:00Z", false, NOW).text).toBe("Scanned today.");
  });
});

describe("findingsLine", () => {
  it("lists only the kinds there are, most serious first, with the right plural", () => {
    expect(findingsLine({ critical: 1, high: 0, medium: 2, low: 0, info: 3, total: 6 })).toBe("6 findings: 1 critical, 2 medium, 3 info.");
    expect(findingsLine({ critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 })).toBe("1 finding: 1 high.");
  });
  it("says there were none, and says nothing when the server gave no counts", () => {
    expect(findingsLine({ critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 })).toBe("No findings.");
    expect(findingsLine(null)).toBeNull();
  });
});

describe("coverageLine / heading", () => {
  it("words the coverage, or says nothing", () => {
    expect(coverageLine({ ran: 41, total: 45 })).toBe("41 of 45 tests ran.");
    expect(coverageLine(null)).toBeNull();
  });
  it("is the owner's name, or the domain", () => {
    expect(heading({ displayName: "Acme Ltd", domain: "shop.example.com" })).toBe("Acme Ltd");
    expect(heading({ displayName: null, domain: "shop.example.com" })).toBe("shop.example.com");
  });
});

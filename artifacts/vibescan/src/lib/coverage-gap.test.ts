import { describe, it, expect } from "vitest";
import { verificationGap, scannedHost, verifyHref, exampleList, NOT_VERIFIED_PREFIX } from "./coverage-gap";

// The exact text the server writes (api-server/src/lib/testLedger.ts, NOT_VERIFIED).
const NOT_VERIFIED = "domain not verified for this account (active tests need proof of ownership)";

const t = (name: string, status: string, reason?: string) => ({ name, status, reason });

describe("verificationGap", () => {
  it("counts only the tests skipped for want of a verified domain", () => {
    const gap = verificationGap([
      t("HTTP methods", "skipped", NOT_VERIFIED),
      t("API surface discovery", "skipped", NOT_VERIFIED),
      t("cross-account access control", "skipped", "needs two accounts"),
      t("JWT analysis", "ran"),
    ]);
    expect(gap.count).toBe(2);
    expect(gap.names).toEqual(["HTTP methods", "API surface discovery"]);
    expect(gap.total).toBe(4);
  });

  it("does not count a test that ran, or one that failed, even with that reason text", () => {
    // Only a skip is a gap. A failed test is a different problem and says so itself.
    expect(verificationGap([t("x", "ran", NOT_VERIFIED), t("y", "failed", NOT_VERIFIED)]).count).toBe(0);
  });

  it("lists a repeated name once", () => {
    const gap = verificationGap([t("active", "skipped", NOT_VERIFIED), t("active", "skipped", NOT_VERIFIED)]);
    expect(gap.count).toBe(2);
    expect(gap.names).toEqual(["active"]);
  });

  it("is empty for a scan with nothing skipped, an empty ledger, or no ledger at all", () => {
    expect(verificationGap([t("a", "ran")]).count).toBe(0);
    expect(verificationGap([]).count).toBe(0);
    expect(verificationGap(null).count).toBe(0);
    expect(verificationGap(undefined).count).toBe(0);
  });

  it("ignores a skip with no reason", () => {
    expect(verificationGap([t("a", "skipped")]).count).toBe(0);
  });

  it("matches the server's reason text", () => {
    expect(NOT_VERIFIED.startsWith(NOT_VERIFIED_PREFIX)).toBe(true);
  });
});

describe("scannedHost and verifyHref", () => {
  it("reads the hostname, lower-cased, without port or path", () => {
    expect(scannedHost("https://My-App.Example.com:8443/a/b?c=d")).toBe("my-app.example.com");
  });

  it("is null for anything that is not an address", () => {
    expect(scannedHost("not a url")).toBeNull();
    expect(scannedHost("")).toBeNull();
    expect(scannedHost(null)).toBeNull();
  });

  it("links the verification page with the domain filled in", () => {
    expect(verifyHref("https://app.example.com/dashboard")).toBe("/domains?domain=app.example.com");
  });

  it("falls back to the bare page when the address does not parse", () => {
    expect(verifyHref("nope")).toBe("/domains");
  });
});

describe("exampleList", () => {
  it("reads naturally for one, two and three names", () => {
    expect(exampleList(["A"])).toBe("A");
    expect(exampleList(["A", "B"])).toBe("A and B");
    expect(exampleList(["A", "B", "C"])).toBe("A, B and C");
  });

  it("caps at four and counts the rest", () => {
    expect(exampleList(["A", "B", "C", "D", "E", "F"])).toBe("A, B, C, D and 2 more");
  });

  it("is empty for none", () => {
    expect(exampleList([])).toBe("");
  });
});

import { describe, it, expect } from "vitest";
import { planDisplayName, planScansLine, planPerScanLabel, fairUseText } from "./billing-api";

describe("planDisplayName", () => {
  it("names the plan on sale and the withdrawn ones", () => {
    expect(planDisplayName("unlimited")).toBe("SecScan Unlimited");
    expect(planDisplayName("starter")).toBe("SecScan Starter");
    expect(planDisplayName("pro")).toBe("SecScan Pro");
  });

  it("reads as plain SecScan for a plan this build does not know, never as Pro", () => {
    // The old code showed "SecScan Pro" for anything that was not "starter", so the new
    // plan would have been labelled with the wrong product's name.
    for (const key of ["grandfathered", "studio", "", "constructor"]) {
      expect(planDisplayName(key), key).toBe("SecScan");
    }
  });
});

describe("planScansLine", () => {
  it("says unlimited for an unlimited plan, whatever its counter holds", () => {
    expect(planScansLine({ unlimitedScans: true, includedScans: 0 })).toBe("Unlimited full scans (fair use)");
    expect(planScansLine({ unlimitedScans: true, includedScans: 999 })).toBe("Unlimited full scans (fair use)");
  });

  it("puts the daily and hourly cap beside \"unlimited\" when the server states them", () => {
    expect(planScansLine({ unlimitedScans: true, includedScans: 0 }, { perHour: 5, perDay: 20 })).toBe(
      "Unlimited full scans (fair use: up to 5 scans an hour and 20 a day)",
    );
  });

  it("gives the monthly count for a counted plan", () => {
    expect(planScansLine({ unlimitedScans: false, includedScans: 20 })).toBe("20 full scans every month");
  });
});

describe("fairUseText", () => {
  it("states the caps when known, and says only fair use when not", () => {
    expect(fairUseText({ perHour: 8, perDay: 40 })).toBe("fair use: up to 8 scans an hour and 40 a day");
    expect(fairUseText(undefined)).toBe("fair use");
  });
});

describe("planPerScanLabel", () => {
  it("has no per-scan price for an unlimited plan, where it would read as divide-by-zero", () => {
    expect(planPerScanLabel({ unlimitedScans: true, includedScans: 0, amountCents: 1900 })).toBeNull();
  });

  it("is null for a counted plan with no scans, instead of Infinity", () => {
    expect(planPerScanLabel({ unlimitedScans: false, includedScans: 0, amountCents: 1900 })).toBeNull();
  });

  it("prices a counted plan per scan", () => {
    expect(planPerScanLabel({ unlimitedScans: false, includedScans: 20, amountCents: 1900 })).toBe("$0.95 per scan");
    expect(planPerScanLabel({ unlimitedScans: false, includedScans: 100, amountCents: 4900 })).toBe("$0.49 per scan");
  });
});

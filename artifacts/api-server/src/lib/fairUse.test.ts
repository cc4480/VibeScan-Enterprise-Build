import { describe, it, expect, afterEach } from "vitest";
import { scanLimitsForPricing, fairUseText } from "./fairUse";

describe("scanLimitsForPricing", () => {
  afterEach(() => {
    delete process.env["SCAN_LIMIT_PER_HOUR"];
    delete process.env["SCAN_LIMIT_PER_DAY"];
  });

  it("reports the limiter's defaults: 5 an hour and 20 a day", () => {
    expect(scanLimitsForPricing()).toEqual({ perHour: 5, perDay: 20 });
  });

  it("follows the operator's settings, so the pricing cannot state a cap the limiter does not enforce", () => {
    process.env["SCAN_LIMIT_PER_HOUR"] = "8";
    process.env["SCAN_LIMIT_PER_DAY"] = "40";
    expect(scanLimitsForPricing()).toEqual({ perHour: 8, perDay: 40 });
  });
});

describe("fairUseText", () => {
  it("says the cap in words", () => {
    expect(fairUseText({ perHour: 5, perDay: 20 })).toBe("fair use: up to 5 scans an hour and 20 a day");
  });
});

import { describe, it, expect } from "vitest";
import { certAlertThresholds } from "./monitorPulseCert";

const day = 86_400_000;
const expires = new Date("2026-12-31T00:00:00Z");

describe("certAlertThresholds", () => {
  it("skips the 30-day warning for a 90-day (auto-renewing) certificate", () => {
    expect(certAlertThresholds(new Date(expires.getTime() - 90 * day), expires)).toEqual([14, 7]);
  });

  it("keeps the 30-day warning for a yearly certificate", () => {
    expect(certAlertThresholds(new Date(expires.getTime() - 397 * day), expires)).toEqual([30, 14, 7]);
  });

  it("keeps the 30-day warning when the issue date is unknown", () => {
    expect(certAlertThresholds(null, expires)).toEqual([30, 14, 7]);
    expect(certAlertThresholds(new Date("not a date"), expires)).toEqual([30, 14, 7]);
  });
});

import { describe, it, expect } from "vitest";
import { summariseReport } from "./apiV1Report";

describe("summariseReport", () => {
  it("counts findings by severity and reports the grade", () => {
    const s = summariseReport({
      summary: { grade: "C", riskScore: 40 },
      vulnerabilities: [{ severity: "critical" }, { severity: "HIGH" }, { severity: "low" }, { severity: "weird" }],
    });
    expect(s.grade).toBe("C");
    expect(s.riskScore).toBe(40);
    expect(s.findings).toEqual({ critical: 1, high: 1, medium: 0, low: 1, info: 0, total: 4 });
  });

  it("leaves the scan's own notes out of the counts and counts them apart", () => {
    const s = summariseReport({ vulnerabilities: [
      { severity: "high", category: "Security Headers" },
      { severity: "info", category: "Security Headers" },
      { severity: "info", category: "Scan Coverage" },
      { severity: "info", category: "Scan Coverage" },
    ] });
    expect(s.findings).toEqual({ critical: 0, high: 1, medium: 0, low: 0, info: 1, total: 2 });
    expect(s.scanNotes).toBe(2);
  });

  it("reports what ran and what did not, never a bare grade", () => {
    const s = summariseReport({ tests: [
      { group: "g", name: "a", status: "ran", findings: 0, durationMs: 1 },
      { group: "g", name: "b", status: "skipped", findings: 0, durationMs: 0 },
      { group: "g", name: "c", status: "failed", findings: 0, durationMs: 0 },
    ] });
    expect(s.coverage).toEqual({ ran: 1, skipped: 1, failed: 1, total: 3 });
  });

  it("leaves out what an older report does not have, instead of inventing zeros", () => {
    const s = summariseReport({ summary: { grade: "A" } });
    expect(s).toEqual({ grade: "A" });
    expect(s.findings).toBeUndefined();
    expect(s.coverage).toBeUndefined();
  });

  it("survives anything that is not a report", () => {
    for (const bad of [null, undefined, 5, "x", [], { vulnerabilities: "no" }]) expect(() => summariseReport(bad)).not.toThrow();
    expect(summariseReport(null)).toEqual({});
  });
});

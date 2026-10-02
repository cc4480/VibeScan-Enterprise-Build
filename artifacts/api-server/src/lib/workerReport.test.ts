import { describe, it, expect, vi } from "vitest";

// The real grade functions; the rest of the scanner is not needed to build a report.
vi.mock("./scanner", () => import("./scannerGrade"));
vi.mock("./monitorPulseCert", () => ({ probeCertDates: () => Promise.resolve(null) }));
vi.mock("./aiAnalysis", () => ({ analyseFindings: () => Promise.resolve({ analysis: null }) }));
vi.mock("./compliance", () => ({ summariseCompliance: () => [], COMPLIANCE_DISCLAIMER: "" }));

import { buildReport } from "./workerReport";

const vuln = (name: string, severity: string, category = "Security Headers") => ({
  id: name, name, severity, category, description: "d", solution: "s", evidence: "e", confidence: 90,
});
const note = (name: string) => vuln(name, "info", "Scan Coverage");

function build(vulnerabilities: unknown[], extra: Record<string, unknown> = {}) {
  return buildReport({
    scanResult: {
      vulnerabilities, technologies: [], server: null, tlsGrade: null, pagesScanned: [], probedNotFound: [],
      finalUrl: "https://example.com/", requestDurationMs: 1, intercepted: false, ...extra,
    } as never,
    targetUrl: "https://example.com",
    tests: [],
    reconRunResult: null as never,
    aiAnalysis: null,
    autoSuppressedCount: 0,
  });
}

describe("buildReport counts findings about the site, not the scan's own notes", () => {
  it("leaves notes out of the stored totals and the returned counts, and keeps them in the list", async () => {
    const out = await build([vuln("a", "high"), vuln("b", "low"), vuln("c", "info"), note("n1"), note("n2")]);
    expect(out.reportData.summary).toMatchObject({ totalVulnerabilities: 3, high: 1, low: 1, info: 1, critical: 0, medium: 0 });
    expect(out.severityCounts).toEqual({ high: 1, low: 1, info: 1 });
    expect(out.reportData.vulnerabilities).toHaveLength(5);
  });

  it("does not let notes move the score or the grade", async () => {
    const withNotes = await build([vuln("a", "high"), note("n1"), note("n2")]);
    const without = await build([vuln("a", "high")]);
    expect(withNotes.riskScore).toBe(without.riskScore);
    expect(withNotes.grade).toBe(without.grade);
  });

  it("says no significant vulnerabilities, not 'identified 2 findings', for a scan that left only notes", async () => {
    const out = await build([note("n1"), note("n2")]);
    expect(out.reportData.summary.totalVulnerabilities).toBe(0);
    expect(out.executiveSummary).toContain("found no significant vulnerabilities");
    expect(out.executiveSummary).not.toContain("identified");
  });

  it("counts only real findings in the executive summary", async () => {
    const out = await build([vuln("a", "low"), note("n1")]);
    expect(out.executiveSummary).toContain("identified 1 security finding, none of them critical or high");
  });

  it("reports no findings for a scan a sign-in page answered, and still does not grade it", async () => {
    const out = await build([note("n1"), note("n2")], { intercepted: true, interception: { kind: "sign-in wall", vendor: null } });
    expect(out.reportData.summary).toMatchObject({ totalVulnerabilities: 0, info: 0, grade: "N/A", intercepted: true });
    expect(out.executiveSummary).toContain("reached a sign-in page");
  });
});

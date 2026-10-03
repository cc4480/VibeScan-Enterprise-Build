import { describe, it, expect } from "vitest";
import { withNoteFreeTotals } from "./reportTotals";
import { buildExecutiveSummary } from "./executiveSummary";

const finding = (severity: string, category = "Security Headers") => ({ category, name: `${severity} ${category}`, severity });
const note = () => ({ category: "Scan Coverage", name: "Active security testing was skipped for this scan", severity: "info" });

// A report as saved before the server left notes out of its totals: 1 finding and 1 note, counted as 2.
function oldReport(targetUrl = "https://example.com/") {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 2 };
  return {
    targetUrl,
    vulnerabilities: [finding("info"), note()],
    summary: {
      totalVulnerabilities: 2,
      ...counts,
      riskScore: 0,
      grade: "A",
      intercepted: false,
      executiveSummary: buildExecutiveSummary("A", 0, targetUrl, 2, counts),
    },
  };
}

describe("withNoteFreeTotals", () => {
  it("recounts a report saved with its notes in the totals", () => {
    const out = withNoteFreeTotals(oldReport());
    expect(out.summary.totalVulnerabilities).toBe(1);
    expect(out.summary.info).toBe(1);
    expect(out.vulnerabilities).toHaveLength(2); // the notes stay in the list
  });

  it("rewrites the executive summary only when it is the text written from the stored counts", () => {
    const out = withNoteFreeTotals(oldReport());
    expect(out.summary.executiveSummary).toBe(buildExecutiveSummary("A", 0, "https://example.com/", 1, { critical: 0, high: 0, medium: 0, low: 0, info: 1 }));
    expect(out.summary.executiveSummary).toContain("1 security finding,");

    const other = oldReport();
    other.summary.executiveSummary = "A text this server did not write from those counts.";
    expect(withNoteFreeTotals(other).summary.executiveSummary).toBe("A text this server did not write from those counts.");
  });

  it("leaves the score, the grade and everything else alone", () => {
    const r = oldReport();
    const out = withNoteFreeTotals({ ...r, tests: ["x"] });
    expect(out.summary.riskScore).toBe(0);
    expect(out.summary.grade).toBe("A");
    expect(out.tests).toEqual(["x"]);
  });

  it("does not touch a report whose totals already leave the notes out", () => {
    const r = oldReport();
    r.summary.totalVulnerabilities = 1;
    r.summary.info = 1;
    expect(withNoteFreeTotals(r)).toBe(r);
  });

  it("does not touch a report with no notes, even if its totals disagree with the list", () => {
    const r = { vulnerabilities: [finding("high")], summary: { totalVulnerabilities: 5, high: 5 } };
    expect(withNoteFreeTotals(r)).toBe(r);
  });

  it("counts each severity from the findings and not from the notes", () => {
    const r = {
      targetUrl: "https://example.com/",
      vulnerabilities: [finding("critical"), finding("high"), finding("high"), note(), note(), finding("low")],
      summary: { totalVulnerabilities: 6, critical: 1, high: 2, medium: 0, low: 1, info: 2, riskScore: 70, grade: "D", intercepted: false, executiveSummary: "x" },
    };
    const s = withNoteFreeTotals(r).summary;
    expect([s.totalVulnerabilities, s.critical, s.high, s.medium, s.low, s.info]).toEqual([4, 1, 2, 0, 1, 0]);
  });

  it("does not rewrite the text of a withheld scan", () => {
    const r = oldReport();
    r.summary.intercepted = true;
    r.summary.executiveSummary = "The scan of example.com reached a sign-in page.";
    const out = withNoteFreeTotals(r);
    expect(out.summary.totalVulnerabilities).toBe(1);
    expect(out.summary.executiveSummary).toBe("The scan of example.com reached a sign-in page.");
  });

  it("returns anything that is not a report as it came", () => {
    expect(withNoteFreeTotals(null)).toBeNull();
    expect(withNoteFreeTotals("x")).toBe("x");
    const noList = { summary: { totalVulnerabilities: 2 } };
    expect(withNoteFreeTotals(noList)).toBe(noList);
    const noSummary = { vulnerabilities: [note()] };
    expect(withNoteFreeTotals(noSummary)).toBe(noSummary);
  });
});

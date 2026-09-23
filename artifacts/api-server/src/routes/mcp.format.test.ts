import { describe, it, expect } from "vitest";
import { formatReport } from "./mcp";

/**
 * The report text an AI editor receives. Sized against a real vuln-fixture
 * scan (180 findings), where an unpaged report came to ~37k characters.
 */
const SEV = ["critical", "high", "medium", "low", "info"] as const;
function report(n: number) {
  const vulnerabilities = Array.from({ length: n }, (_, i) => ({
    id: String(i), name: `Finding ${i}`, severity: SEV[i % 5], category: "x",
    description: "d".repeat(900), solution: "s".repeat(900), evidence: "e".repeat(900),
  }));
  return {
    id: "r1", targetUrl: "https://example.com", scannedAt: new Date("2026-09-22T00:00:00Z"),
    data: {
      summary: { grade: "F", riskScore: 100, critical: n / 5, high: n / 5, medium: n / 5, low: n / 5, info: n / 5, executiveSummary: "Summary text." },
      vulnerabilities,
      aiAnalysis: { topPriorities: ["Fix the worst"], agentFixPrompt: "EDITOR PROMPT" },
      compliance: { disclaimer: "DISCLAIMER" },
    },
  };
}
const count = (t: string) => (t.match(/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/gm) ?? []).length;

describe("formatReport paging", () => {
  it("returns a bounded first page, most severe first, with the narrative once", () => {
    const t = formatReport(report(180));
    expect(count(t)).toBe(25);
    expect(t).toContain("Findings 1–25 of 180");
    // 36 criticals, so a most-severe-first page of 25 is all critical.
    expect((t.match(/^\[CRITICAL\]/gm) ?? []).length).toBe(25);
    expect(t).toContain("EDITOR PROMPT");
    expect(t).toContain("DISCLAIMER");
    expect(t).toContain("155 more. Call get_report with offset 25");
    // ~2k chars per finding at worst (clipped fields) keeps a page well under 25k tokens.
    expect(t.length).toBeLessThan(40_000);
  });

  it("clips long fields so one finding cannot flood the page", () => {
    const t = formatReport(report(5));
    expect(t).not.toContain("d".repeat(700));
    expect(t).not.toContain("e".repeat(400));
  });

  it("walks every finding exactly once across pages, sending the narrative only on page 1", () => {
    let seen = 0, offset = 0, pages = 0;
    for (;;) {
      const t = formatReport(report(180), { offset });
      const n = count(t);
      if (pages > 0) {
        expect(t).not.toContain("EDITOR PROMPT");
        expect(t).not.toContain("DISCLAIMER");
      }
      seen += n; offset += n; pages++;
      if (!t.includes("Call get_report with offset")) break;
    }
    expect(seen).toBe(180);
    expect(pages).toBe(8);
  });

  it("filters by severity and says so, including in the next-page hint", () => {
    const t = formatReport(report(180), { minSeverity: "high" });
    expect(t).toContain("of 72 at high or above");
    expect(t).not.toMatch(/^\[(MEDIUM|LOW|INFO)\]/m);
    expect(t).toContain('min_severity "high"');
  });

  it("answers plainly past the end, and for a clean report", () => {
    expect(formatReport(report(10), { offset: 50 })).toContain("No findings at offset 50 — there are 10");
    expect(formatReport(report(0))).toContain("No findings.");
  });

  it("caps the page size", () => {
    expect(count(formatReport(report(180), { limit: 500 }))).toBe(50);
  });
});

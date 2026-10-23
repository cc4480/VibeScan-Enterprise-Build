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

describe("formatReport shows what the scan tested", () => {
  const withTests = (tests: unknown) => {
    const r = report(5);
    (r.data as any).tests = tests;
    return r;
  };

  it("puts coverage next to the grade, so a clean grade cannot read as full coverage", () => {
    const t = formatReport(withTests([
      { group: "passive", name: "headers", status: "ran", findings: 0, durationMs: 1 },
      { group: "active", name: "injection (XSS, SQLi)", status: "skipped", findings: 0, durationMs: 0, reason: "domain not verified for this account" },
    ]));
    expect(t).toContain("What this scan tested: 1 of 2 tests ran, 1 skipped, 0 failed.");
    expect(t).toContain("- injection (XSS, SQLi) (active): domain not verified for this account");
    // Before the summary and the findings, directly under the report link.
    expect(t.indexOf("What this scan tested")).toBeLessThan(t.indexOf("Summary:"));
    expect(t.indexOf("What this scan tested")).toBeGreaterThan(t.indexOf("Full report:"));
  });

  it("says so on a report from before test records existed", () => {
    expect(formatReport(report(5))).toContain("What this scan tested: not recorded");
  });

  it("sends coverage once, on the first page only", () => {
    const first = formatReport(withTests([{ group: "g", name: "a", status: "ran", findings: 0, durationMs: 1 }]));
    const second = formatReport(withTests([{ group: "g", name: "a", status: "ran", findings: 0, durationMs: 1 }]), { offset: 3 });
    expect(first).toContain("What this scan tested");
    expect(second).not.toContain("What this scan tested");
  });
});

describe("formatReport keeps the scan's own notes apart from the findings", () => {
  const note = (name: string) => ({ id: name, name, severity: "info", category: "Scan Coverage", description: `About ${name}.`, solution: "", evidence: "" });
  const finding = (name: string, severity: string) => ({ id: name, name, severity, category: "x", description: "d", solution: "s", evidence: "" });
  const rep = (vulnerabilities: unknown[], summary: Record<string, unknown> = {}) => ({
    id: "r1", targetUrl: "https://example.com", scannedAt: new Date("2026-09-22T00:00:00Z"),
    data: { summary: { grade: "B", riskScore: 15, ...summary }, vulnerabilities },
  });

  it("lists them under About this scan, on the first page, and not among the findings", () => {
    const t = formatReport(rep([finding("Real", "high"), note("Active testing skipped"), note("No browser")]));
    expect(t).toContain("Findings 1–1 of 1");
    expect(count(t)).toBe(1);
    expect(t).toContain("About this scan (2 notes)");
    expect(t).toContain("- Active testing skipped: About Active testing skipped.");
    expect(formatReport(rep([finding("Real", "high"), note("n")]), { offset: 1 })).not.toContain("About this scan");
  });

  it("counts the line from the list, so a summary that counted a note does not show", () => {
    const t = formatReport(rep([finding("Real", "low"), note("n")], { low: 1, info: 1 }));
    expect(t).toContain("0 high, 0 medium, 1 low, 0 info");
  });

  it("does not call a report with only notes clean", () => {
    const t = formatReport(rep([note("n")]));
    expect(t).toContain("No findings were reported. Read the notes under");
    expect(t).not.toContain("No findings.");
    expect(formatReport(rep([note("n")]), { minSeverity: "high" })).toContain("No findings at high or above.");
  });
});

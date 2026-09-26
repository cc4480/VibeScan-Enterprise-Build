import { describe, it, expect } from "vitest";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildHtml } from "./mailer";

/**
 * The report-ready email. Set EMAIL_PREVIEW_DIR to also write the rendered HTML
 * there for a visual check.
 */
const base = {
  toEmail: "owner@example.com",
  targetUrl: "https://secscan.us/",
  grade: "A",
  riskScore: 6,
  totalVulns: 3,
  reportUrl: "https://secscan.us/report/abc-123",
  tier: "deep",
  coverage: { ran: 38, skipped: 1, failed: 0, total: 39 },
  severity: { critical: 0, high: 0, medium: 1, low: 1, info: 1 },
};

describe("report-ready email: what changed", () => {
  it("shows the change line when there is one, escaped", () => {
    const html = buildHtml({ ...base, changesLine: "2 new, 3 fixed since your last scan (20 Sep)" });
    expect(html).toContain("2 new, 3 fixed since your last scan (20 Sep)");
    expect(buildHtml({ ...base, changesLine: "<script>x</script>" })).not.toContain("<script>x</script>");
  });

  it("has no such line on a first scan or when nothing changed", () => {
    expect(buildHtml(base)).not.toContain("since your last scan");
    expect(buildHtml({ ...base, changesLine: "" })).not.toContain("since your last scan");
  });
});

describe("report-ready email", () => {
  it("links the button to the full report page", () => {
    const html = buildHtml(base);
    expect(html).toContain('href="https://secscan.us/report/abc-123"');
    expect(html).toContain("View Full Report");
    expect(html).not.toContain("/share/");
  });

  it("does not let mail clients turn the scanned site into a link", () => {
    const html = buildHtml(base);
    expect(html).toContain("secscan.&#8203;us");
    expect(html).toContain("https:&#8203;//");
    expect(html).not.toMatch(/href="https:\/\/secscan\.us\/"/);
  });

  it("shows the grade, score, findings, tests run and every severity", () => {
    const html = buildHtml(base);
    for (const s of [">A<", "6<span", "38<span", "/39", "Medium", "Low", "Info"]) {
      expect(html).toContain(s);
    }
  });

  it("says plainly when tests did not run", () => {
    expect(buildHtml(base)).toContain("1 test did not run");
    expect(buildHtml({ ...base, coverage: { ran: 39, skipped: 0, failed: 0, total: 39 } })).not.toContain("did not run");
  });

  it("leads with what matters", () => {
    expect(buildHtml(base)).toContain("No critical or high-severity issues found.");
    expect(buildHtml({ ...base, severity: { ...base.severity, critical: 2 } })).toContain("2 critical issues need fixing now.");
    expect(buildHtml({ ...base, severity: { ...base.severity, high: 1 } })).toContain("1 high-severity issue needs attention.");
    expect(buildHtml({ ...base, totalVulns: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } })).toContain(
      "No issues found by the tests that ran.",
    );
  });

  it("carries the app's brand: logo, grade ring, report title, primary green", () => {
    const html = buildHtml({ ...base, executiveSummary: "Security scan of secscan.us identified 3 findings.", pagesScanned: 13 });
    expect(html).toContain("/icon-192.png");
    expect(html).toContain("Security Report");
    expect(html).toContain("RISK: 6");
    expect(html).toContain("Scanned 13 pages");
    expect(html).toContain("Security scan of secscan.us identified 3 findings.");
    expect(html).toContain("#22c55e");
    expect(html).not.toContain("#6366f1");
  });

  it("escapes a hostile target URL", () => {
    const html = buildHtml({ ...base, targetUrl: 'https://x.test/"><script>alert(1)</script>' });
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("writes previews when asked", () => {
    const dir = process.env["EMAIL_PREVIEW_DIR"];
    if (!dir) return;
    writeFileSync(
      join(dir, "a.html"),
      buildHtml({ ...base, executiveSummary: "Security scan of secscan.us identified 3 security findings, none of them critical or high, yielding an overall grade of A with a risk score of 6/100.", pagesScanned: 13 }),
    );
    writeFileSync(
      join(dir, "d.html"),
      buildHtml({
        ...base,
        targetUrl: "https://shop.example.com/",
        grade: "D",
        riskScore: 64,
        totalVulns: 11,
        coverage: { ran: 22, skipped: 16, failed: 1, total: 39 },
        severity: { critical: 1, high: 3, medium: 4, low: 2, info: 1 },
      }),
    );
  });
});

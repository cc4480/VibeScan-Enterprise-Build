import { describe, it, expect } from "vitest";
import { TestLedger, formatTestLine, formatTestSummary, NOT_VERIFIED, coverageLines } from "./testLedger";

const finding = { id: "1", name: "x", severity: "low", category: "c", description: "d", solution: "s" } as const;

describe("TestLedger", () => {
  it("records a test that ran, with its finding count, and passes the result through untouched", async () => {
    const ledger = new TestLedger();
    const out = await ledger.track("active", "injection", Promise.resolve([finding, finding]));
    expect(out).toHaveLength(2);
    expect(ledger.records[0]).toMatchObject({ group: "active", name: "injection", status: "ran", findings: 2 });
  });

  it("records a test that threw as failed, and re-throws so existing failure handling still sees it", async () => {
    const ledger = new TestLedger();
    await expect(ledger.track("passive", "DNS", Promise.reject(new Error("timeout")))).rejects.toThrow("timeout");
    expect(ledger.records[0]).toMatchObject({ name: "DNS", status: "failed", reason: "timeout" });
  });

  it("records a skip with its reason", () => {
    const ledger = new TestLedger();
    ledger.skip("active", "path traversal", NOT_VERIFIED);
    expect(ledger.summary()).toEqual({ ran: 0, skipped: 1, failed: 0, total: 1 });
  });
});

describe("the console lines", () => {
  it("says what ran, how long and what it found", () => {
    expect(formatTestLine({ group: "active", name: "injection (XSS, SQLi)", status: "ran", findings: 1, durationMs: 379 }))
      .toBe("[test] RAN     active · injection (XSS, SQLi) — 1 finding, 379 ms");
  });

  it("says why a test was skipped", () => {
    expect(formatTestLine({ group: "active", name: "SSRF", status: "skipped", findings: 0, durationMs: 0, reason: "no callback host" }))
      .toBe("[test] SKIPPED active · SSRF — skipped: no callback host");
  });

  it("says how a test failed", () => {
    expect(formatTestLine({ group: "passive", name: "DNS", status: "failed", findings: 0, durationMs: 8000, reason: "timeout" }))
      .toBe("[test] FAILED  passive · DNS — failed after 8000 ms: timeout");
  });

  it("totals them", () => {
    expect(
      formatTestSummary([
        { group: "a", name: "1", status: "ran", findings: 0, durationMs: 1 },
        { group: "a", name: "2", status: "skipped", findings: 0, durationMs: 0 },
        { group: "a", name: "3", status: "failed", findings: 0, durationMs: 1 },
      ]),
    ).toBe("[tests] 1 ran, 1 skipped, 1 failed (3 total)");
  });
});

describe("coverageLines — what the report says was tested", () => {
  const rec = (name: string, status: "ran" | "skipped" | "failed", reason?: string) => ({
    group: "g", name, status, findings: 0, durationMs: 1, ...(reason ? { reason } : {}),
  });

  it("says plainly when everything ran", () => {
    expect(coverageLines([rec("a", "ran"), rec("b", "ran")])[0]).toBe("What this scan tested: all 2 tests ran.");
  });

  it("lists what was not tested, with the reason, so a clean grade is not read as full coverage", () => {
    const t = coverageLines([
      rec("headers", "ran"),
      rec("injection (XSS, SQLi)", "skipped", "domain not verified for this account"),
      rec("SSL Labs", "failed", "assessment unavailable"),
    ]).join("\n");
    expect(t).toContain("1 of 3 tests ran, 1 skipped, 1 failed");
    expect(t).toContain("a clean result says nothing about these");
    expect(t).toContain("- injection (XSS, SQLi) (g): domain not verified for this account");
    expect(t).toContain("- SSL Labs (g): failed to run — assessment unavailable");
    expect(t).not.toContain("- headers");
  });

  it("states that older reports have no record instead of implying full coverage", () => {
    for (const none of [undefined, null, [], "nope", [{ junk: 1 }]]) {
      expect(coverageLines(none).join("\n")).toContain("not recorded");
    }
  });

  it("ignores malformed entries without throwing", () => {
    const t = coverageLines([rec("ok", "ran"), null, 5, { name: "x", status: "weird" }]).join("\n");
    expect(t).toContain("all 1 tests ran");
  });

  it("caps a very long list", () => {
    const many = Array.from({ length: 40 }, (_, i) => rec(`t${i}`, "skipped", "r"));
    const lines = coverageLines(many);
    expect(lines.join("\n")).toContain("…and 15 more.");
    expect(lines.length).toBeLessThan(35);
  });
});

describe("countTests", () => {
  it("counts each outcome and the total", async () => {
    const { countTests } = await import("./testLedger");
    expect(
      countTests([
        { group: "a", name: "1", status: "ran", findings: 0, durationMs: 1 },
        { group: "a", name: "2", status: "skipped", findings: 0, durationMs: 0 },
        { group: "a", name: "3", status: "failed", findings: 0, durationMs: 1 },
        { group: "a", name: "4", status: "ran", findings: 2, durationMs: 1 },
      ]),
    ).toEqual({ ran: 2, skipped: 1, failed: 1, total: 4 });
  });
});

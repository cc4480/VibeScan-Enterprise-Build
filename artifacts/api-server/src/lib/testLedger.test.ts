import { describe, it, expect } from "vitest";
import { TestLedger, formatTestLine, formatTestSummary, NOT_VERIFIED } from "./testLedger";

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

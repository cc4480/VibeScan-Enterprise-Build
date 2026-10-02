import { describe, it, expect } from "vitest";
import { TestLedger, formatTestLine, formatTestSummary, NOT_VERIFIED, coverageLines, newlyRunTests, foundNames, MAX_FOUND_NAMES } from "./testLedger";

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

describe("the finding names a record keeps", () => {
  const named = (n: number) => Array.from({ length: n }, (_, i) => ({ ...finding, id: String(i), name: `Finding ${i}` }));

  it("keeps every name of a test that raised many findings, in order, so none reads 'which check raised this was not recorded'", async () => {
    // The vulnerable fixture raises 78 from its sensitive-file test; the old limit of 40 left 38 of them unnamed.
    const ledger = new TestLedger();
    await ledger.track("HTTP probes", "sensitive file exposure", Promise.resolve(named(78)));
    const rec = ledger.records[0]!;
    expect(rec.findings).toBe(78);
    expect(rec.found).toHaveLength(78);
    expect(rec.found?.[0]).toBe("Finding 0");
    expect(rec.found?.[77]).toBe("Finding 77");
  });

  it("keeps every name for a probe recorded through trackOutcome too", async () => {
    const ledger = new TestLedger();
    await ledger.trackOutcome("active", "API endpoint testing", Promise.resolve({ findings: named(78) }));
    expect(ledger.records[0]?.found).toHaveLength(78);
  });

  it("keeps no list for a test that found nothing", async () => {
    const ledger = new TestLedger();
    await ledger.track("active", "SSRF", Promise.resolve([]));
    expect(ledger.records[0]).not.toHaveProperty("found");
  });

  it("stops at MAX_FOUND_NAMES, and the count still says how many were raised", async () => {
    const ledger = new TestLedger();
    await ledger.track("active", "everything", Promise.resolve(named(MAX_FOUND_NAMES + 25)));
    const rec = ledger.records[0]!;
    expect(rec.found).toHaveLength(MAX_FOUND_NAMES);
    expect(rec.findings).toBe(MAX_FOUND_NAMES + 25);
    // checkOutcomes treats fewer names than findings as "names incomplete", which is how the cut shows.
    expect(rec.found!.length).toBeLessThan(rec.findings);
  });

  it("foundNames is the same list for the sites that write a record without the ledger's methods", () => {
    expect(foundNames(named(3))).toEqual(["Finding 0", "Finding 1", "Finding 2"]);
    expect(foundNames(named(MAX_FOUND_NAMES + 1))).toHaveLength(MAX_FOUND_NAMES);
    expect(foundNames([])).toEqual([]);
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

describe("newlyRunTests — when a new finding may be called a regression", () => {
  const rec = (name: string, status: "ran" | "skipped" | "failed", group = "active") => ({
    group, name, status, findings: 0, durationMs: 1,
  });

  it("lists tests that ran now but were skipped last time (domain verified in between)", () => {
    const before = [rec("injection (XSS, SQLi)", "skipped"), rec("JWT analysis", "ran", "passive")];
    const now = [rec("injection (XSS, SQLi)", "ran"), rec("JWT analysis", "ran", "passive")];
    expect(newlyRunTests(before, now)).toEqual(["injection (XSS, SQLi)"]);
  });

  it("is empty when the same tests ran both times, so real regressions still count", () => {
    const both = [rec("injection (XSS, SQLi)", "ran"), rec("JWT analysis", "ran", "passive")];
    expect(newlyRunTests(both, both)).toEqual([]);
  });

  it("ignores per-scan counts in a test's name", () => {
    expect(newlyRunTests([rec("site crawl (12 inner pages)", "ran", "crawl")], [rec("site crawl (15 inner pages)", "ran", "crawl")])).toEqual([]);
  });

  it("claims nothing when the previous scan kept no ledger", () => {
    expect(newlyRunTests(undefined, [rec("injection", "ran")])).toEqual([]);
    expect(newlyRunTests([], [rec("injection", "ran")])).toEqual([]);
  });

  it("a test that ran before and is skipped now is not 'newly run'", () => {
    expect(newlyRunTests([rec("port scan", "ran", "recon")], [rec("port scan", "skipped", "recon")])).toEqual([]);
  });
});

describe("TestLedger.trackOutcome — a test that compared nothing is not a clean test", () => {
  it("records ran when the probe says what it tested", async () => {
    const ledger = new TestLedger();
    const out = await ledger.trackOutcome("active", "idor", Promise.resolve({ findings: [] }));
    expect(out).toEqual([]);
    expect(ledger.records[0]).toMatchObject({ status: "ran", findings: 0 });
  });

  it("records skipped, with the reason, when the probe reports it tested nothing", async () => {
    const ledger = new TestLedger();
    const out = await ledger.trackOutcome("active", "idor", Promise.resolve({ findings: [], notTested: "no record could be compared" }));
    expect(out).toEqual([]);
    expect(ledger.records[0]).toMatchObject({ status: "skipped", findings: 0, reason: "no record could be compared" });
    expect(ledger.summary()).toMatchObject({ ran: 0, skipped: 1 });
  });

  it("still counts a finding as a run, whatever notTested says", async () => {
    const ledger = new TestLedger();
    await ledger.trackOutcome("active", "idor", Promise.resolve({ findings: [finding], notTested: "stale" }));
    expect(ledger.records[0]).toMatchObject({ status: "ran", findings: 1 });
  });

  it("records failed and re-throws, like track", async () => {
    const ledger = new TestLedger();
    await expect(ledger.trackOutcome("active", "x", Promise.reject(new Error("boom")))).rejects.toThrow("boom");
    expect(ledger.records[0]).toMatchObject({ status: "failed", reason: "boom" });
  });

  it("makes the coverage line stop saying all tests ran", async () => {
    const ledger = new TestLedger();
    await ledger.trackOutcome("active", "cross-account access control (IDOR)", Promise.resolve({ findings: [], notTested: "compared nothing" }));
    const lines = coverageLines(ledger.records);
    expect(lines[0]).not.toMatch(/all \d+ tests ran/);
    expect(lines.join("\n")).toContain("compared nothing");
  });
});

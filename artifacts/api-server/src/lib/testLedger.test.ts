import { describe, it, expect } from "vitest";
import { TestLedger, formatTestLine, formatTestSummary, NOT_VERIFIED, coverageLines, newlyRunTests, foundNames, MAX_FOUND_NAMES, sourceLines } from "./testLedger";

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

describe("NOT_VERIFIED", () => {
  it("still starts with the text the report's verification banner looks for", () => {
    // The front end (vibescan/src/lib/coverage-gap.ts, NOT_VERIFIED_PREFIX) finds the tests skipped
    // for want of a verified domain by this prefix. Rewording it without updating that file would
    // silently remove the banner from every report, so this fails first.
    expect(NOT_VERIFIED.startsWith("domain not verified")).toBe(true);
  });
});

describe("sourceLines — the repository section of a report as text", () => {
  const rec = (status: "ran" | "skipped" | "failed", extra: object = {}) => ({
    group: "passive", name: "GitHub source code secrets", status, findings: 0, durationMs: 1, ...extra,
  });
  const repoVuln = { name: "Hardcoded Stripe key (in source repository)", evidence: "Repository: acme/app\nFile: .env" };

  it("says nothing when the scan was given no repository", () => {
    expect(sourceLines([rec("skipped", { reason: "no repository was supplied for this scan" })])).toEqual([]);
    expect(sourceLines([])).toEqual([]);
    expect(sourceLines(undefined)).toEqual([]);
  });

  it("says how much was read and what each check found, for a clean repository", () => {
    const text = sourceLines([
      rec("ran", { source: { repository: "acme/app", via: "github-app", read: 12, treeFiles: 400, checks: [
        { name: "repository secrets", files: 4, findings: 0 },
        { name: "CI and configuration", files: 0, findings: 0, note: "no matching files in the repository" },
      ] } }),
    ]).join("\n");
    expect(text).toContain("Source code (acme/app): read 12 files of 400 in the repository, through the connected GitHub App.");
    expect(text).toContain("- repository secrets: 4 files read, 0 findings");
    expect(text).toContain("- CI and configuration: no matching files in the repository");
    expect(text).toContain("Nothing was found in the files that were read.");
  });

  it("lists what was found in the repository, and only that", () => {
    const text = sourceLines(
      [rec("ran", { findings: 1, source: { repository: "acme/app", read: 3 } })],
      [repoVuln, { name: "Missing HSTS", evidence: "Header absent" }],
    ).join("\n");
    expect(text).toContain("Found in the repository: Hardcoded Stripe key (in source repository).");
    expect(text).not.toContain("Missing HSTS");
  });

  it("says a repository that was not read says nothing about its code", () => {
    const text = sourceLines([rec("skipped", { reason: "the repository is private", source: { repository: "acme/app" } })]).join("\n");
    expect(text).toContain("Source code (acme/app): the repository was not read — the repository is private.");
    expect(text).toContain("says nothing about this code");
  });

  it("warns when part of the repository could not be read", () => {
    const text = sourceLines([rec("ran", { source: { repository: "acme/app", read: 300, leftOut: 40 } })]).join("\n");
    expect(text).toContain("covers only the files that were read");
  });
});

describe("sourceLines — scans from before the record kept what was read", () => {
  it("says the check ran but not what it read, and does not say nothing was found", () => {
    const text = sourceLines([{ group: "passive", name: "GitHub source code secrets", status: "ran", findings: 0, durationMs: 1 }]).join("\n");
    expect(text).toContain("what it read was not recorded");
    expect(text).not.toContain("Nothing was found");
  });

  it("still says a given repository was not read, when its name was not recorded", () => {
    const text = sourceLines([{ group: "passive", name: "GitHub source code secrets", status: "skipped", findings: 0, durationMs: 0, reason: "the repository is private or does not exist" }]).join("\n");
    expect(text).toContain("the repository was not read");
  });
});

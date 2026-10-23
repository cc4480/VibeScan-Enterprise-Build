import { describe, it, expect } from "vitest";
import { resolveTest } from "./checkOutcomes";
import type { TestRecord } from "./testLedger";

const rec = (over: Partial<TestRecord>): TestRecord => ({
  group: "passive",
  name: "JWT analysis",
  status: "ran",
  findings: 0,
  durationMs: 10,
  ...over,
});
const outcomes = (r: TestRecord) => resolveTest(r).checks.map((c) => c.outcome);

describe("resolveTest: a check is only shown as clear when that is certain", () => {
  it("shows every check clear when the test ran and found nothing", () => {
    const t = resolveTest(rec({}));
    expect(t.checks).toHaveLength(6);
    expect(new Set(outcomes(rec({})))).toEqual(new Set(["clear"]));
    expect(t.category).toBe("Session Management");
  });

  it("never shows a skipped or failed test's checks as clear", () => {
    expect(new Set(outcomes(rec({ status: "skipped", reason: "x" })))).toEqual(new Set(["not_run"]));
    expect(new Set(outcomes(rec({ status: "failed", reason: "boom" })))).toEqual(new Set(["not_run"]));
  });

  it("marks the check that fired, and only that one, when every finding is matched", () => {
    const t = resolveTest(rec({ findings: 1, found: ["JWT Using alg:none — Signature Verification Bypass"] }));
    const fired = t.checks.filter((c) => c.outcome === "finding").map((c) => c.name);
    expect(fired).toEqual(["JWT Using alg:none — Signature Verification Bypass"]);
    expect(t.checks.filter((c) => c.outcome === "clear")).toHaveLength(5);
  });

  it("matches a check whose finding name carries variable text", () => {
    const t = resolveTest(rec({ findings: 1, found: ["JWT Token Lifetime Is 900 Days — Excessive"] }));
    expect(t.checks.find((c) => c.outcome === "finding")?.name).toBe("JWT Token Lifetime Excessive");
  });

  it("will not claim clear when a finding cannot be placed on any check", () => {
    const t = resolveTest(rec({ findings: 2, found: ["JWT Using alg:none — Signature Verification Bypass"] }));
    // Two findings, only one named: the other could belong to any check.
    expect(t.checks.filter((c) => c.outcome === "clear")).toHaveLength(0);
    expect(t.checks.filter((c) => c.outcome === "checked").length).toBeGreaterThan(0);
  });

  it("will not claim clear when the finding names were not recorded", () => {
    expect(new Set(outcomes(rec({ findings: 1 })))).toEqual(new Set(["checked"]));
  });

  it("attributes leftover findings to the one check that has no literal name, only when all names are known", () => {
    const crawl = rec({ name: "site crawl (14 inner pages)", findings: 1, found: [".env File Exposed"] });
    const t = resolveTest(crawl);
    expect(t.checks.find((c) => c.name.startsWith("Sensitive path found"))?.outcome).toBe("finding");
    // Without the names, the same test only says "checked".
    expect(new Set(outcomes({ ...crawl, found: undefined }))).toEqual(new Set(["checked"]));
  });

  it("returns no checks for a step that raises no findings of its own", () => {
    const t = resolveTest(rec({ name: "DNS records (12)" }));
    expect(t.checks).toEqual([]);
    expect(t.category).toBeNull();
  });

  it("keeps a per-check category where the test spans two (cookies vs headers)", () => {
    const t = resolveTest(rec({ name: "response headers and cookies" }));
    expect(t.category).toBe("HTTP Security");
    expect(t.checks.find((c) => c.name.startsWith("Session Cookie Missing Secure"))?.category).toBe("Session Management");
  });
});

import { describe, it, expect } from "vitest";
import { diffScans, summariseChanges, testFor } from "./scanDiff";

const t = (name: string, status: "ran" | "skipped" | "failed" = "ran") => ({ group: "g", name, status, findings: 0, durationMs: 1 });
const f = (name: string, severity = "medium", category = "HTTP Security", evidence = "") => ({ name, severity, category, evidence });
const scan = (vulns: unknown[], tests: unknown[]) => ({ vulnerabilities: vulns, tests });
const prev = (data: unknown, credentialed = false) => ({ scanId: "s0", scannedAt: "2026-09-20T10:00:00Z", data, credentialed });

const HEADERS = "response headers and cookies";
const JWT = "JWT analysis";
const CORS = "active CORS";
const CSP = "Missing Content-Security-Policy (CSP)";
const JWT_NONE = "JWT Using alg:none — Signature Verification Bypass";
const CORS_REFLECT = "CORS — Origin Reflected Without Credentials";

describe("diffScans: like with like", () => {
  const tests = [t(HEADERS), t(JWT), t(CORS)];

  it("finds what is new, what is fixed and what is unchanged", () => {
    const c = diffScans(
      prev(scan([f(CSP, "high"), f("Missing Referrer-Policy Header", "low")], tests)),
      { data: scan([f("Missing Referrer-Policy Header", "low"), f(JWT_NONE, "critical", "Session Management")], tests) },
    );
    expect(c.fixed.map((x) => x.name)).toEqual([CSP]);
    expect(c.added.map((x) => x.name)).toEqual([JWT_NONE]);
    expect(c.unchanged).toBe(1);
    expect(c.firstSeen).toEqual([]);
    expect(c.notRechecked).toEqual([]);
  });

  it("orders each list by severity, worst first", () => {
    const c = diffScans(prev(scan([], tests)), { data: scan([f("Missing Referrer-Policy Header", "low"), f(JWT_NONE, "critical"), f(CSP, "high")], tests) });
    expect(c.added.map((x) => x.severity)).toEqual(["critical", "high", "low"]);
  });

  it("says nothing changed when nothing did", () => {
    const c = diffScans(prev(scan([f(CSP)], tests)), { data: scan([f(CSP)], tests) });
    expect(c.added.length + c.fixed.length + c.firstSeen.length + c.notRechecked.length).toBe(0);
    expect(summariseChanges(c)).toBe("");
  });
});

describe("diffScans: a finding that vanished was not necessarily fixed", () => {
  it("does NOT call a finding fixed when its test did not run this time", () => {
    const before = scan([f(CORS_REFLECT, "high", "CORS Misconfiguration")], [t(HEADERS), t(CORS)]);
    const now = scan([], [t(HEADERS), t(CORS, "skipped")]); // domain no longer verified: CORS not tested
    const c = diffScans(prev(before), { data: now });
    expect(c.fixed).toEqual([]);
    expect(c.notRechecked.map((x) => x.name)).toEqual([CORS_REFLECT]);
    expect(c.noLongerRun).toContain("active CORS");
  });

  it("does not call it fixed when its test failed, either", () => {
    const c = diffScans(prev(scan([f(JWT_NONE, "critical")], [t(JWT)])), { data: scan([], [t(JWT, "failed")]) });
    expect(c.fixed).toEqual([]);
    expect(c.notRechecked).toHaveLength(1);
  });

  it("calls it fixed when its test ran again and it is gone, even if other tests changed", () => {
    const c = diffScans(prev(scan([f(CSP, "high")], [t(HEADERS), t(CORS)])), { data: scan([], [t(HEADERS), t(CORS, "skipped")]) });
    expect(c.fixed.map((x) => x.name)).toEqual([CSP]);
  });

  it("never calls anything fixed when there is no ledger to check against (an old report)", () => {
    const c = diffScans(prev({ vulnerabilities: [f(CSP, "high")] }), { data: { vulnerabilities: [] } });
    expect(c.fixed).toEqual([]);
    expect(c.notRechecked).toHaveLength(1);
  });
});

describe("diffScans: a new finding may only be new to us", () => {
  it("labels a finding from a test that did not run last time as first seen, not new", () => {
    const c = diffScans(
      prev(scan([], [t(HEADERS), t(CORS, "skipped")])),
      { data: scan([f(CORS_REFLECT, "high", "CORS Misconfiguration")], [t(HEADERS), t(CORS)]) }, // domain verified in between
    );
    expect(c.added).toEqual([]);
    expect(c.firstSeen.map((x) => x.name)).toEqual([CORS_REFLECT]);
    expect(c.newlyRun).toContain("active CORS");
  });

  it("still calls a finding new when its own test ran last time too", () => {
    const c = diffScans(prev(scan([], [t(HEADERS), t(CORS, "skipped")])), { data: scan([f(CSP, "high")], [t(HEADERS), t(CORS)]) });
    expect(c.added.map((x) => x.name)).toEqual([CSP]);
  });

  it("judges an unmappable finding by the whole ledger", () => {
    const unknown = f("Some Finding No Catalog Entry Names");
    const same = diffScans(prev(scan([], [t(HEADERS)])), { data: scan([unknown], [t(HEADERS)]) });
    expect(same.added).toHaveLength(1);
    const grew = diffScans(prev(scan([], [t(HEADERS)])), { data: scan([unknown], [t(HEADERS), t(JWT)]) });
    expect(grew.added).toEqual([]);
    expect(grew.firstSeen).toHaveLength(1);
  });
});

describe("diffScans: notices and access", () => {
  it("ignores scan-coverage notices: they are not security findings", () => {
    const notice = f("Active security testing was skipped for this scan", "info", "Scan Coverage");
    const c = diffScans(prev(scan([notice], [t(HEADERS)])), { data: scan([], [t(HEADERS)]) });
    expect(c.fixed).toEqual([]);
    expect(c.notRechecked).toEqual([]);
  });

  it("warns when one scan used a login and the other did not", () => {
    expect(diffScans(prev(scan([], [t(HEADERS)]), true), { data: scan([], [t(HEADERS)]), credentialed: false }).differentAccess).toBe(true);
    expect(diffScans(prev(scan([], [t(HEADERS)]), true), { data: scan([], [t(HEADERS)]), credentialed: true }).differentAccess).toBe(false);
  });

  it("survives malformed reports on either side", () => {
    for (const bad of [null, undefined, "x", {}, { vulnerabilities: "no", tests: 5 }]) {
      expect(() => diffScans(prev(bad), { data: bad })).not.toThrow();
    }
  });
});

describe("testFor", () => {
  it("maps a finding to the test that raises it, including names with variable parts", () => {
    expect(testFor(CSP)).toBe(HEADERS);
    expect(testFor("JWT Token Lifetime Is 900 Days — Excessive")).toBe(JWT);
    expect(testFor(CORS_REFLECT)).toBe(CORS);
  });
  it("returns null for a name nothing in the catalog can raise", () => {
    expect(testFor("Something Else Entirely")).toBeNull();
  });
});

describe("summariseChanges", () => {
  it("states new, fixed and not re-checked, with the date", () => {
    const c = diffScans(
      prev(scan([f(CSP, "high"), f(CORS_REFLECT, "high")], [t(HEADERS), t(CORS)])),
      { data: scan([f(JWT_NONE, "critical")], [t(HEADERS), t(JWT), t(CORS, "skipped")]) },
    );
    expect(summariseChanges(c)).toMatch(/^1 new, 1 fixed, 1 not re-checked since your last scan \(20 Sep\)$/);
  });
});

import { verdictFor } from "./scanDiff";

describe("verdictFor: the verdict on one finding after a fix", () => {
  const before = scan([f(CSP, "high"), f(CORS_REFLECT, "high", "CORS Misconfiguration")], [t(HEADERS), t(CORS)]);
  const asked = { name: CSP, category: "HTTP Security" };
  const askedCors = { name: CORS_REFLECT, category: "CORS Misconfiguration" };

  it("still_present when the new scan finds it again", () => {
    expect(verdictFor(before, scan([f(CSP, "high")], [t(HEADERS), t(CORS)]), asked)).toBe("still_present");
  });

  it("fixed when it is gone and its test ran again", () => {
    expect(verdictFor(before, scan([], [t(HEADERS), t(CORS)]), asked)).toBe("fixed");
  });

  it("not_rechecked when it is gone but its test did not run: never called fixed", () => {
    expect(verdictFor(before, scan([], [t(HEADERS), t(CORS, "skipped")]), askedCors)).toBe("not_rechecked");
    expect(verdictFor(before, scan([], [t(HEADERS), t(CORS, "failed")]), askedCors)).toBe("not_rechecked");
    expect(verdictFor(before, scan([], [t(HEADERS)]), askedCors)).toBe("not_rechecked");
  });

  it("judges by the test that raises THIS finding, not the others", () => {
    // CORS is skipped, but the asked-about finding comes from the headers test, which ran.
    expect(verdictFor(before, scan([], [t(HEADERS), t(CORS, "skipped")]), asked)).toBe("fixed");
  });

  it("an unmappable finding is fixed only if every earlier test ran again", () => {
    const unknown = { name: "Some Finding No Catalog Entry Names", category: "X" };
    const b = scan([{ ...f(unknown.name), category: "X" }], [t(HEADERS), t(CORS)]);
    expect(verdictFor(b, scan([], [t(HEADERS), t(CORS)]), unknown)).toBe("fixed");
    expect(verdictFor(b, scan([], [t(HEADERS)]), unknown)).toBe("not_rechecked");
  });

  it("not_rechecked with no ledger to check against, and survives malformed data", () => {
    expect(verdictFor({ vulnerabilities: [f(CSP)] }, { vulnerabilities: [] }, { name: "Unmapped", category: "x" })).toBe("not_rechecked");
    for (const bad of [null, undefined, "x", {}]) expect(() => verdictFor(bad, bad, asked)).not.toThrow();
  });
});

describe("diffScans: a repository finding is fixed only if its file was read again", () => {
  const SRC = "GitHub source code secrets";
  const tests = [t(HEADERS), t(SRC)];
  const RLS = "Supabase Tables Created Without Row Level Security";
  const repoEvidence = (file: string) => `Repository: acme/app\nFile: ${file}\nTables: admin_config`;
  const PARTIAL = { name: "GitHub source scan covered only part of the repository", severity: "info", category: "Scan Coverage", evidence: "Repository: acme/app\nFile: (repository)" };

  it("does not call it fixed when its file is now left out as a test target", () => {
    const fixture = f(RLS, "high", "Broken Access Control", repoEvidence("test-targets/tier3/supabase/migrations/0001.sql"));
    const c = diffScans(prev(scan([fixture], tests)), { data: scan([], tests) });
    expect(c.fixed).toEqual([]);
    expect(c.notRechecked.map((x) => x.name)).toEqual([RLS]);
  });

  it("does not call it fixed when this scan read only part of the repository", () => {
    const own = f(RLS, "high", "Broken Access Control", repoEvidence("supabase/migrations/0001.sql"));
    const c = diffScans(prev(scan([own], tests)), { data: scan([PARTIAL], tests) });
    expect(c.fixed).toEqual([]);
    expect(c.notRechecked.map((x) => x.name)).toEqual([RLS]);
  });

  it("calls it fixed in a partial scan that recorded reading its file", () => {
    const own = f(RLS, "high", "Broken Access Control", repoEvidence("supabase/migrations/0001.sql"));
    const partial = { ...PARTIAL, repoFilesRead: ["README.md", "supabase/migrations/0001.sql"] };
    const c = diffScans(prev(scan([own], tests)), { data: scan([partial], tests) });
    expect(c.fixed.map((x) => x.name)).toEqual([RLS]);
  });

  it("does not call it fixed in a partial scan whose recorded list lacks its file", () => {
    const own = f(RLS, "high", "Broken Access Control", repoEvidence("supabase/migrations/0001.sql"));
    const partial = { ...PARTIAL, repoFilesRead: ["README.md"] };
    const c = diffScans(prev(scan([own], tests)), { data: scan([partial], tests) });
    expect(c.fixed).toEqual([]);
    expect(c.notRechecked.map((x) => x.name)).toEqual([RLS]);
  });

  it("still calls it fixed when the whole repository was read and the file is the project's own", () => {
    const own = f(RLS, "high", "Broken Access Control", repoEvidence("supabase/migrations/0001.sql"));
    const c = diffScans(prev(scan([own], tests)), { data: scan([], tests) });
    expect(c.fixed.map((x) => x.name)).toEqual([RLS]);
    expect(c.notRechecked).toEqual([]);
  });

  it("leaves findings that are not from a repository alone, even in a partial repository scan", () => {
    const c = diffScans(prev(scan([f(CSP, "high")], tests)), { data: scan([PARTIAL], tests) });
    expect(c.fixed.map((x) => x.name)).toEqual([CSP]);
  });
});

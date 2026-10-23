import { describe, it, expect } from "vitest";
import { owaspCoverage, owaspFindingCounts, type TestLike } from "./owaspCoverage";

const ran = (name: string): TestLike => ({ name, status: "ran" });
const skipped = (name: string): TestLike => ({ name, status: "skipped" });

/** The shape of a scan of a domain that was NOT verified: every active test skipped. */
const UNVERIFIED_SCAN: TestLike[] = [
  ran("HTTP probes (headers, files, methods, CORS)"),
  ran("DNS and email authentication"),
  ran("known-CVE and end-of-life versions"),
  ran("JWT analysis"),
  ran("JavaScript secret scanning"),
  ran("TLS configuration check (TLS 1.3 negotiated, certificate valid for 60 more days)"),
  skipped("injection (XSS, SQLi)"),
  skipped("path traversal"),
  skipped("API endpoint testing (auth, injection, IDOR, mass assignment)"),
  skipped("cross-account access control (IDOR)"),
  skipped("SSRF (out-of-band callback)"),
];

describe("owaspCoverage: a category with no findings is not automatically 'passed'", () => {
  it("does not tick Injection when the injection tests were skipped", () => {
    // The bug in the screenshot: a green tick beside 'Injection' on a scan that never ran the
    // injection tests.
    expect(owaspCoverage("A03", 0, UNVERIFIED_SCAN).state).toBe("untested");
  });

  it("does not tick Broken Access Control when every access-control test was skipped", () => {
    const r = owaspCoverage("A01", 0, UNVERIFIED_SCAN);
    expect(r.state).toBe("untested");
    expect(r.notRun).toContain("cross-account access control (IDOR)");
  });

  it("ticks categories whose tests all ran and found nothing", () => {
    expect(owaspCoverage("A06", 0, UNVERIFIED_SCAN).state).toBe("clear");
    expect(owaspCoverage("A02", 0, UNVERIFIED_SCAN).state).toBe("clear");
    expect(owaspCoverage("A05", 0, UNVERIFIED_SCAN).state).toBe("clear");
  });

  it("calls a category partly tested when only some of its tests ran", () => {
    const r = owaspCoverage("A07", 0, UNVERIFIED_SCAN);
    // JWT analysis and HTTP probes ran; API endpoint testing and cross-account did not.
    expect(r.state).toBe("partial");
    expect(r.notRun).toEqual(
      expect.arrayContaining(["API endpoint testing (auth, injection, IDOR, mass assignment)", "cross-account access control (IDOR)"]),
    );
  });

  it("clears everything once the domain is verified and every test runs", () => {
    const all = UNVERIFIED_SCAN.map((t) => ({ ...t, status: "ran" as const }));
    for (const code of ["A01", "A02", "A03", "A05", "A06", "A07", "A08"]) {
      expect(owaspCoverage(code, 0, all).state).toBe("clear");
    }
  });

  it("reads the TLS configuration check, and SSL Labs when an operator has enabled it, as covering A02", () => {
    // A02 is covered by the TLS check, the mail transport check and the HTTP probes.
    const withoutTls = UNVERIFIED_SCAN.filter((t) => !t.name.startsWith("TLS configuration check"));
    expect(owaspCoverage("A02", 0, withoutTls).state).toBe("clear"); // HTTP probes alone still cover it
    const tlsSkipped = [...withoutTls, skipped("TLS configuration check")];
    const r = owaspCoverage("A02", 0, tlsSkipped);
    expect(r.state).toBe("partial");
    expect(r.notRun).toEqual(["TLS configuration check"]);
    expect(owaspCoverage("A02", 0, [ran("SSL Labs TLS grade (A)")]).state).toBe("clear");
    expect(owaspCoverage("A02", 0, [skipped("TLS configuration check")]).state).toBe("untested");
  });

  it("flags a category with findings whatever ran", () => {
    expect(owaspCoverage("A03", 2, UNVERIFIED_SCAN).state).toBe("flagged");
    expect(owaspCoverage("A03", 1, undefined).state).toBe("flagged");
  });

  it("says nothing on a report with no test record, instead of ticking", () => {
    for (const none of [undefined, null, []]) expect(owaspCoverage("A03", 0, none).state).toBe("unknown");
  });

  it("does not tick a category no recorded test speaks to", () => {
    expect(owaspCoverage("A08", 0, [ran("DNS and email authentication")]).state).toBe("untested");
    expect(owaspCoverage("A99", 0, UNVERIFIED_SCAN).state).toBe("untested");
  });

  it("treats a failed test like a skipped one", () => {
    const r = owaspCoverage("A06", 0, [{ name: "known-CVE and end-of-life versions", status: "failed" }]);
    expect(r.state).toBe("untested");
  });
});

describe("owaspFindingCounts", () => {
  it("does not let an informational note flag a category", () => {
    const counts = owaspFindingCounts([
      { category: "Browser Feature Control", severity: "info" },
      { category: "Transport Security", severity: "medium" },
    ]);
    expect(counts.A05).toEqual({ actionable: 0, info: 1 });
    expect(counts.A02).toEqual({ actionable: 1, info: 0 });
    expect(owaspCoverage("A05", counts.A05!.actionable, [{ name: "HTTP probes", status: "ran" }]).state).toBe("clear");
  });
});

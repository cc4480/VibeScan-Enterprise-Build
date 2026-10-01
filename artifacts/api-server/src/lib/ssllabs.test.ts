import { describe, it, expect } from "vitest";
import { explainGrade } from "./ssllabs";
import { tlsGradeNote, mergeSslLabs } from "./workerSideChecks";
import type { ScanResult } from "./scanner";

describe("explainGrade", () => {
  it("names obsolete protocols and missing forward secrecy from SSL Labs' own details", () => {
    const reasons = explainGrade({
      grade: "B",
      details: {
        protocols: [{ name: "TLS", version: "1.0" }, { name: "TLS", version: "1.1" }, { name: "TLS", version: "1.2" }, { name: "TLS", version: "1.3" }],
        forwardSecrecy: 1,
      },
    });
    expect(reasons).toHaveLength(2);
    expect(reasons[0]).toMatch(/TLS 1\.0 and TLS 1\.1/);
    expect(reasons[1]).toMatch(/Forward secrecy is not used with modern browsers/);
  });

  it("reports nothing it was not told: a modern server, or no details, yields no reasons", () => {
    expect(explainGrade({ grade: "A", details: { protocols: [{ name: "TLS", version: "1.2" }, { name: "TLS", version: "1.3" }], forwardSecrecy: 4 } })).toEqual([]);
    expect(explainGrade({ grade: "B" })).toEqual([]);
    expect(explainGrade(undefined)).toEqual([]);
  });

  it("reports known attacks only when SSL Labs says the server is vulnerable", () => {
    expect(explainGrade({ details: { heartbleed: true, poodleTls: 2, openSslCcs: 1 } }).join(" ")).toMatch(/Heartbleed.*POODLE/);
    expect(explainGrade({ details: { heartbleed: false, poodleTls: 1, openSslCcs: 1 } })).toEqual([]);
  });
});

describe("TLS grade note", () => {
  const base = { grade: "B", hasWarnings: false, isExceptional: false, issues: [], reportUrl: "https://www.ssllabs.com/ssltest/analyze.html?d=example.com" };

  it("lists the reasons and the full report", () => {
    const v = tlsGradeNote({ ...base, reasons: ["The server still accepts TLS 1.0, which is obsolete."] });
    expect(v.severity).toBe("info");
    expect(v.description).toMatch(/graded this site's TLS configuration B, not A.*TLS 1\.0/);
    expect(v.evidence).toMatch(/Full report: https:\/\/www\.ssllabs\.com/);
  });

  it("says plainly when SSL Labs gave no cause, and guesses none", () => {
    const v = tlsGradeNote({ ...base, reasons: [] });
    expect(v.description).toMatch(/did not name a specific cause/);
  });

  it("is added for B and A- but not for A, A+ or C and below (those have their own finding)", () => {
    const run = (grade: string) => {
      const r = { vulnerabilities: [], tlsGrade: null } as unknown as ScanResult;
      mergeSslLabs(r, { ...base, grade, reasons: [] }, { info() {}, warn() {} } as never);
      return r.vulnerabilities.map((v) => v.name);
    };
    expect(run("B")).toEqual(["TLS Grade Below A (SSL Labs)"]);
    expect(run("A-")).toEqual(["TLS Grade Below A (SSL Labs)"]);
    expect(run("A")).toEqual([]);
    expect(run("A+")).toEqual([]);
    expect(run("C")).toEqual(["Weak TLS Configuration (SSL Labs Grade: C)"]);
  });
});

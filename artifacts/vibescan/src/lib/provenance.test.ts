import { describe, it, expect } from "vitest";
import { findingProvenance, confidenceText } from "./provenance";

const tests = [
  { group: "passive", name: "response headers and cookies", status: "ran" as const, found: ["Missing Content-Security-Policy (CSP)"] },
  { group: "active", name: "injection (XSS, SQLi)", status: "ran" as const, found: ["Reflected XSS"] },
  { group: "HTTP probes", name: "sensitive file exposure", status: "ran" as const },
];

describe("findingProvenance", () => {
  it("names the check that raised the finding and says it only observed", () => {
    const p = findingProvenance(
      { name: "Missing Content-Security-Policy (CSP)", category: "Security Headers", evidence: "GET https://a.test/\nContent-Security-Policy: (header absent)" },
      tests,
    );
    expect(p).toEqual({ check: "response headers and cookies", kind: "observation", requests: ["GET https://a.test/"] });
  });

  it("marks findings from active groups as active tests", () => {
    expect(findingProvenance({ name: "Reflected XSS", category: "Injection", evidence: "" }, tests).kind).toBe("active");
  });

  it("does not guess when no test record names the finding", () => {
    const p = findingProvenance({ name: "Exposed .env", category: "Exposure", evidence: "GET https://a.test/.env → HTTP 200" }, tests);
    expect(p.check).toBeNull();
    expect(p.kind).toBe("unknown");
    expect(p.requests).toEqual(["GET https://a.test/.env → HTTP 200"]);
  });

  it("treats Scan Coverage entries as notes about the scan", () => {
    expect(findingProvenance({ name: "x", category: "Scan Coverage" }, tests).kind).toBe("scan note");
  });

  it("keeps at most five request lines and ignores prose", () => {
    const evidence = ["Some prose GET /x mentioned", ...Array.from({ length: 7 }, (_, i) => `GET /api/${i} → HTTP 200`)].join("\n");
    expect(findingProvenance({ name: "y", category: "API", evidence }, null).requests).toHaveLength(5);
  });
});

describe("confidenceText", () => {
  it("explains the number", () => {
    expect(confidenceText(95)).toMatch(/seen directly/);
    expect(confidenceText(60)).toMatch(/inferred/);
    expect(confidenceText(30)).toMatch(/weak signal/);
    expect(confidenceText(null)).toBeNull();
  });
});

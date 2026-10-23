import { describe, it, expect } from "vitest";
import { findingProvenance, confidenceText, ACTIVE_NO_REQUESTS_TEXT } from "./provenance";

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

  describe("requests an active test wrote on a labelled line", () => {
    const xss = { name: "Reflected XSS", category: "Injection" };

    it("reads a 'Request: METHOD url' line", () => {
      const p = findingProvenance({ ...xss, evidence: "Request: POST https://a.test/api/ask\nPayload reflected unescaped" }, tests);
      expect(p.kind).toBe("active");
      expect(p.requests).toEqual(["Request: POST https://a.test/api/ask"]);
    });

    it("reads a 'Request:' line for an observation too, since the line names a method", () => {
      const p = findingProvenance(
        { name: "Missing Content-Security-Policy (CSP)", category: "Security Headers", evidence: "Request: GET https://a.test/" },
        tests,
      );
      expect(p.kind).toBe("observation");
      expect(p.requests).toEqual(["Request: GET https://a.test/"]);
    });

    it("reads an 'Endpoint:' line for an active test only", () => {
      const evidence = "Endpoint: /search?q=<script>alert(1)</script>\nReflected without encoding";
      expect(findingProvenance({ ...xss, evidence }, tests).requests).toEqual(["Endpoint: /search?q=<script>alert(1)</script>"]);
      // A passive finding's "Endpoint:" line may only say where something was seen, not what was sent.
      const passive = findingProvenance({ name: "Missing Content-Security-Policy (CSP)", category: "Security Headers", evidence }, tests);
      expect(passive.kind).toBe("observation");
      expect(passive.requests).toEqual([]);
    });

    it("does not read an 'Endpoint:' line when the check is unknown or the finding is a scan note", () => {
      const evidence = "Endpoint: /search?q=x";
      expect(findingProvenance({ name: "Something else", category: "Injection", evidence }, tests).requests).toEqual([]);
      expect(findingProvenance({ name: "x", category: "Scan Coverage", evidence }, tests).requests).toEqual([]);
    });

    it("ignores a label that is not followed by a method and an address", () => {
      const evidence = ["Request: was blocked by the firewall", "Request: POST (no address)", "Endpoint: unknown"].join("\n");
      expect(findingProvenance({ ...xss, evidence }, tests).requests).toEqual([]);
    });

    it("keeps evidence order and the five-line cap across all three line shapes", () => {
      const evidence = ["GET /a", "Request: POST /b", "Endpoint: /c", "GET /d", "Request: GET /e", "GET /f"].join("\n");
      expect(findingProvenance({ ...xss, evidence }, tests).requests).toEqual(["GET /a", "Request: POST /b", "Endpoint: /c", "GET /d", "Request: GET /e"]);
    });
  });
});

describe("ACTIVE_NO_REQUESTS_TEXT", () => {
  it("speaks about the evidence, and does not claim that no request was sent", () => {
    expect(ACTIVE_NO_REQUESTS_TEXT).toMatch(/evidence lists no request lines/);
    expect(ACTIVE_NO_REQUESTS_TEXT).not.toMatch(/no requests were|did not send|never sent/i);
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

import { describe, it, expect } from "vitest";
import { TOP_PORTS, COMMON_SUBDOMAINS } from "./recon-data.js";

/**
 * First tests for this table. It is data rather than logic, so there is no
 * behaviour to stub — but it carries 14 findings, three of them Critical, and
 * every field goes straight into a customer's report. A typo in a CVSS score
 * or a missing CWE is invisible until someone reads the output.
 *
 * These assert the table's shape, not its opinions: severity and score are
 * judgement calls, but a severity with no score, or a score outside the CVSS
 * range, is simply wrong.
 */

describe("TOP_PORTS — table integrity", () => {
  it("has no duplicate port numbers", () => {
    const ports = TOP_PORTS.map((p) => p.port);
    expect(new Set(ports).size).toBe(ports.length);
  });

  it("gives every port a service name and a valid number", () => {
    for (const p of TOP_PORTS) {
      expect(Number.isInteger(p.port), String(p.port)).toBe(true);
      expect(p.port, String(p.port)).toBeGreaterThan(0);
      expect(p.port, String(p.port)).toBeLessThanOrEqual(65535);
      expect(p.service.trim().length, String(p.port)).toBeGreaterThan(0);
    }
  });

  it("keeps the ports that make a scan worth running", () => {
    // A regression that silently dropped Telnet or SMB would remove findings
    // rather than add them, which no other test would notice.
    const ports = TOP_PORTS.map((p) => p.port);
    for (const expected of [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 6379]) {
      expect(ports, `port ${expected}`).toContain(expected);
    }
  });
});

describe("TOP_PORTS — every dangerous service is fully described", () => {
  const dangerous = TOP_PORTS.filter((p) => p.dangerous);

  it("marks a meaningful number of ports dangerous", () => {
    expect(dangerous.length).toBeGreaterThanOrEqual(10);
  });

  it("carries a description, a solution, a CWE and a CVSS score on each", () => {
    for (const p of dangerous) {
      const d = p.dangerous!;
      expect(d.description.trim().length, `port ${p.port} description`).toBeGreaterThan(40);
      expect(d.solution.trim().length, `port ${p.port} solution`).toBeGreaterThan(20);
      expect(d.cweId, `port ${p.port} cwe`).toMatch(/^CWE-\d+$/);
      expect(["critical", "high", "medium"], `port ${p.port} severity`).toContain(d.severity);
    }
  });

  it("keeps every CVSS score inside the real scale", () => {
    for (const p of dangerous) {
      const s = p.dangerous!.cvssScore;
      expect(s, `port ${p.port}`).toBeGreaterThan(0);
      expect(s, `port ${p.port}`).toBeLessThanOrEqual(10);
    }
  });

  it("keeps severity and score telling the same story", () => {
    // A Critical scored 4.0, or a Medium scored 9.8, means one of the two is a
    // typo — and the report would show both.
    for (const p of TOP_PORTS.filter((x) => x.dangerous)) {
      const { severity, cvssScore } = p.dangerous!;
      if (severity === "critical") expect(cvssScore, `port ${p.port}`).toBeGreaterThanOrEqual(9.0);
      if (severity === "high") expect(cvssScore, `port ${p.port}`).toBeGreaterThanOrEqual(7.0);
      if (severity === "medium") expect(cvssScore, `port ${p.port}`).toBeLessThan(7.0);
    }
  });

  it("uses a well-formed WSTG id wherever one is given", () => {
    for (const p of TOP_PORTS.filter((x) => x.dangerous?.wstgId)) {
      expect(p.dangerous!.wstgId, `port ${p.port}`).toMatch(/^WSTG-[A-Z]+-\d+$/);
    }
  });

  it("still treats plaintext Telnet as critical", () => {
    const telnet = TOP_PORTS.find((p) => p.port === 23);
    expect(telnet?.dangerous?.severity).toBe("critical");
    expect(telnet?.dangerous?.cweId).toBe("CWE-319");
  });
});

describe("COMMON_SUBDOMAINS — wordlist integrity", () => {
  it("contains no duplicates", () => {
    expect(new Set(COMMON_SUBDOMAINS).size).toBe(COMMON_SUBDOMAINS.length);
  });

  it("holds only bare labels, never dots or wildcards", () => {
    // An entry like "www.example" or "*.dev" would be concatenated into a
    // malformed hostname and quietly resolve to nothing on every scan.
    for (const label of COMMON_SUBDOMAINS) {
      expect(label, label).toMatch(/^[a-z0-9][a-z0-9-]*$/);
    }
  });

  it("keeps the labels most likely to expose a non-production environment", () => {
    for (const expected of ["dev", "staging", "test", "admin", "api"]) {
      expect(COMMON_SUBDOMAINS, expected).toContain(expected);
    }
  });
});

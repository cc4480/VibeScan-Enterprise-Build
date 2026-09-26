import { describe, it, expect } from "vitest";
import { toSarif, ruleId, locationUrl } from "./sarif";

const vuln = (over: Record<string, unknown> = {}) => ({
  name: "Missing Content-Security-Policy (CSP)",
  severity: "high",
  category: "HTTP Security",
  description: "No CSP header is set.",
  evidence: "GET https://example.com/app\nContent-Security-Policy: (absent)",
  solution: "Add a Content-Security-Policy header.",
  cweId: "CWE-693",
  ...over,
});
const run = (vulns: unknown[], targetUrl = "https://example.com/") =>
  toSarif({ targetUrl, scannedAt: "2026-09-26T10:00:00Z", data: { vulnerabilities: vulns } }).runs[0]!;

describe("toSarif", () => {
  it("produces a SARIF 2.1.0 log for SecScan with one result per finding", () => {
    const log = toSarif({ targetUrl: "https://example.com/", data: { vulnerabilities: [vuln(), vuln({ name: "Open Redirect Vulnerability", severity: "medium" })] } });
    expect(log.version).toBe("2.1.0");
    expect(log.runs[0]!.tool.driver.name).toBe("SecScan");
    expect(log.runs[0]!.results).toHaveLength(2);
  });

  it("maps severity to a level for CI gating and a number for GitHub's ranking", () => {
    const r = run([vuln({ severity: "critical" }), vuln({ name: "b", severity: "medium" }), vuln({ name: "c", severity: "low" }), vuln({ name: "d", severity: "info" })]);
    expect(r.results.map((x) => x.level)).toEqual(["error", "warning", "note", "note"]);
    const scores = r.tool.driver.rules.map((x) => (x.properties as { "security-severity": string })["security-severity"]);
    expect(scores).toEqual(["9.5", "5.5", "3.0", "1.0"]);
  });

  it("gives the same problem the same rule, so a rule is listed once however often it fires", () => {
    const r = run([vuln(), vuln({ evidence: "GET https://example.com/other" })]);
    expect(r.tool.driver.rules).toHaveLength(1);
    expect(r.results).toHaveLength(2);
    expect(r.results[0]!.ruleId).toBe(r.results[1]!.ruleId);
  });

  it("locates a result at the URL in its evidence, else the scanned site", () => {
    const r = run([vuln(), vuln({ name: "No evidence", evidence: "" })], "https://example.com/");
    expect(r.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe("https://example.com/app");
    expect(r.results[1]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe("https://example.com/");
  });

  it("fingerprints a finding by rule and place, so a fix closes the alert and a rescan does not duplicate it", () => {
    const a = run([vuln()]).results[0]!.partialFingerprints;
    const b = run([vuln({ description: "worded differently now" })]).results[0]!.partialFingerprints;
    const elsewhere = run([vuln({ evidence: "GET https://example.com/different" })]).results[0]!.partialFingerprints;
    expect(a).toEqual(b);
    expect(a).not.toEqual(elsewhere);
  });

  it("carries the fix, the category and the CWE", () => {
    const rule = run([vuln()]).tool.driver.rules[0]!;
    expect((rule.help as { text: string }).text).toBe("Add a Content-Security-Policy header.");
    expect((rule.properties as { tags: string[] }).tags).toEqual(["security", "HTTP Security", "CWE-693"]);
  });

  it("is a valid, empty log for a clean or malformed report", () => {
    for (const data of [{ vulnerabilities: [] }, {}, null, "x", { vulnerabilities: "no" }]) {
      const log = toSarif({ targetUrl: "https://example.com", data });
      expect(log.runs[0]!.results).toEqual([]);
    }
  });

  it("keeps scan-coverage notices out of the alerts and puts them in the run's notifications", () => {
    const notice = { name: "Active security testing was skipped for this scan", severity: "info", category: "Scan Coverage", description: "No verified ownership on record.", evidence: "" };
    const r = run([vuln(), notice]);
    expect(r.results).toHaveLength(1);
    expect(r.tool.driver.rules).toHaveLength(1);
    const notes = (r.invocations[0] as { toolExecutionNotifications?: { message: { text: string } }[] }).toolExecutionNotifications;
    expect(notes).toHaveLength(1);
    expect(notes![0]!.message.text).toContain("Active security testing was skipped");
  });

  it("has no notifications when there was nothing to say", () => {
    expect((run([vuln()]).invocations[0] as { toolExecutionNotifications?: unknown }).toolExecutionNotifications).toBeUndefined();
  });

  it("does not throw on a target that is not a URL", () => {
    expect(() => toSarif({ targetUrl: "not a url", data: {} })).not.toThrow();
  });
});

describe("ruleId and locationUrl", () => {
  it("makes a stable, readable id, distinct for names that slug the same", () => {
    expect(ruleId("Missing CSP")).toBe(ruleId("Missing CSP"));
    expect(ruleId("Missing CSP")).toMatch(/^secscan\/missing-csp-[0-9a-f]{6}$/);
    expect(ruleId("Missing CSP!")).not.toBe(ruleId("Missing CSP?"));
  });

  it("reads a URL out of request-style evidence only", () => {
    expect(locationUrl("POST https://a.example/x?y=1\nbody", "fb")).toBe("https://a.example/x?y=1");
    expect(locationUrl("see https://a.example/x", "fb")).toBe("fb");
    expect(locationUrl("", "fb")).toBe("fb");
  });
});

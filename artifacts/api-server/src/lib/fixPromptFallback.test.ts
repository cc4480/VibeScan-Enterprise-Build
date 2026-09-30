import { describe, it, expect } from "vitest";
import { buildFallbackAnalysis } from "./fixPromptFallback";
import type { ScanVulnerability } from "./scanner";

let n = 0;
const v = (o: Partial<ScanVulnerability>): ScanVulnerability => ({
  id: `id${n++}`,
  name: "Finding",
  severity: "medium",
  category: "Misc",
  description: "Something is wrong. More detail follows here.",
  evidence: "SECRET-EVIDENCE-VALUE",
  solution: "Change the setting.",
  cweId: null,
  cvssScore: null,
  wstgId: null,
  confidence: 90,
  ...o,
});
const build = (vulnerabilities: ScanVulnerability[], agent: "generic" | "lovable" = "generic", tests: never[] = []) =>
  buildFallbackAnalysis({ targetUrl: "https://example.com", vulnerabilities, agent, tests });

describe("buildFallbackAnalysis", () => {
  it("is labelled a template and has an empty prompt when nothing is fixable", () => {
    const r = build([v({ category: "Scan Coverage", severity: "info" })]);
    expect(r.source).toBe("template");
    expect(r.agentFixPrompt).toBe("");
  });

  it("orders the most severe finding first", () => {
    const r = build([v({ name: "Low one", severity: "low" }), v({ name: "Crit one", severity: "critical" })]);
    expect(r.agentFixPrompt.indexOf("Crit one")).toBeLessThan(r.agentFixPrompt.indexOf("Low one"));
    expect(r.topPriorities[0]).toContain("Crit one");
  });

  it("never includes evidence and redacts secret-shaped text", () => {
    const r = build([v({ solution: "Rotate the key sk_live_abcdefghijklmnopqrstuvwxyz123456 now." })]);
    expect(r.agentFixPrompt).not.toContain("SECRET-EVIDENCE-VALUE");
    expect(r.agentFixPrompt).not.toContain("sk_live_abcdefghijklmnopqrstuvwxyz123456");
  });

  it("caps the main list and mentions the rest", () => {
    const r = build(Array.from({ length: 20 }, (_, i) => v({ name: `Issue ${i}`, severity: "high" })));
    expect((r.agentFixPrompt.match(/^## \d+\./gm) ?? []).length).toBe(12);
    expect(r.agentFixPrompt).toContain("8 further findings");
  });

  it("keeps informational findings under an optional heading", () => {
    const r = build([v({ severity: "high", name: "Big" }), v({ severity: "info", name: "Tiny" })]);
    expect(r.agentFixPrompt).toContain("Optional, lower priority");
    expect(r.topPriorities.join()).not.toContain("Tiny");
  });

  it("adds a platform line only for builder platforms", () => {
    expect(build([v({})], "lovable").agentFixPrompt).toContain("app builder");
    expect(build([v({})], "generic").agentFixPrompt).not.toContain("app builder");
  });

  it("says it was assembled without the AI writer", () => {
    expect(build([v({})]).overallRisk).toContain("without the AI writer");
  });
});

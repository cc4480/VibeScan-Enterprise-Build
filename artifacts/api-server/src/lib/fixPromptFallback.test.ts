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

describe("a repository's fix prompt", () => {
  const finding = (name: string, file: string, severity: "medium" | "info" = "info") =>
    ({
      id: `${name}-${file}`, name, severity, category: "Exposed Secrets / Credentials",
      description: `A credential is committed in ${file}. Anyone who can read the repository can read it.`,
      evidence: `Repository: acme/app\nFile: ${file}\nMatch (redacted): sk_liv...klmn`,
      solution: "Rotate the credential now.", cweId: "CWE-798", cvssScore: 0,
    }) as never;

  const analysis = buildFallbackAnalysis({
    targetUrl: "https://github.com/acme/app",
    repository: "acme/app",
    agent: "unknown" as never,
    tests: [],
    vulnerabilities: [
      finding("TLS Certificate Verification Disabled", "server/pgSsl.ts", "medium"),
      finding("Stripe Live Secret Key Exposed (in a test or example file)", "server/a.test.ts"),
      finding("Stripe Live Secret Key Exposed (in a test or example file)", "server/b.test.ts"),
      finding("Stripe Live Secret Key Exposed (in a test or example file)", "docs/c.md"),
    ],
  });

  it("speaks of the repository, not a web app or a black-box scan", () => {
    expect(analysis.agentFixPrompt).toContain("in my repository (acme/app)");
    expect(analysis.agentFixPrompt).not.toMatch(/web app|black-box/i);
  });

  it("names the files of each finding, and merges one finding per file into one entry", () => {
    expect(analysis.agentFixPrompt).toContain("Where: server/pgSsl.ts");
    expect(analysis.agentFixPrompt).toContain("Where: server/a.test.ts, server/b.test.ts, docs/c.md");
    expect(analysis.agentFixPrompt.match(/Stripe Live Secret Key Exposed/g)).toHaveLength(1);
  });

  it("puts the real finding first and the information ones under lower priority, never including a matched value", () => {
    const p = analysis.agentFixPrompt;
    expect(p.indexOf("TLS Certificate Verification Disabled")).toBeLessThan(p.indexOf("Optional, lower priority"));
    expect(p).not.toContain("sk_liv");
  });

  it("still describes a website the old way", () => {
    const site = buildFallbackAnalysis({ targetUrl: "https://acme.dev", agent: "unknown" as never, tests: [], vulnerabilities: [finding("X", "a")] });
    expect(site.agentFixPrompt).toContain("my web app (https://acme.dev)");
    expect(site.agentFixPrompt).not.toContain("Where:");
  });
});

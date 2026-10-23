import { describe, it, expect } from "vitest";
import { everyFindingChecklist, withEveryFinding } from "./fixPromptCoverage";
import type { ScanVulnerability } from "./scanner";

const v = (name: string, severity: string, file?: string): ScanVulnerability => ({
  id: name, name, severity, category: "X", description: "", solution: "",
  evidence: file ? `Repository: a/b\nFile: ${file}\nValue` : "",
}) as ScanVulnerability;

describe("the fix prompt lists every finding in the report", () => {
  it("names the info findings and the repository findings, most severe first, with their files", () => {
    const list = everyFindingChecklist([
      v("Hardcoded JWT Token in Source (in a test or example file)", "info", "server/jwtProbe.test.ts"),
      v("Container Runs as Root", "low", "Dockerfile"),
      v("Vulnerable dependency: anyio 4.13.0", "critical", "uv.lock"),
    ]);
    const lines = list.split("\n");
    expect(lines[0]).toContain("CRITICAL: Vulnerable dependency: anyio 4.13.0 (uv.lock)");
    expect(lines[1]).toContain("LOW: Container Runs as Root (Dockerfile)");
    expect(lines[2]).toContain("INFO: Hardcoded JWT Token in Source (in a test or example file) (server/jwtProbe.test.ts)");
  });

  it("appends the checklist to the model's prompt, and leaves the prompt alone when there are no findings", () => {
    const out = withEveryFinding("Fix the app.", [v("Container Runs as Root", "low", "Dockerfile")]);
    expect(out.startsWith("Fix the app.")).toBe(true);
    expect(out).toContain("1 in total");
    expect(out).toContain("- LOW: Container Runs as Root (Dockerfile)");
    expect(withEveryFinding("None of these needs a code change.", [])).toBe("None of these needs a code change.");
  });

  it("clean twin: a finding with no file is listed by name, with no empty brackets", () => {
    expect(everyFindingChecklist([v("AI analysis could not be completed for this scan", "info")])).toBe("- INFO: AI analysis could not be completed for this scan");
  });
});

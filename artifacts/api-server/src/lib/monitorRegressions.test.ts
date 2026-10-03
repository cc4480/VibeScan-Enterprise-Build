import { describe, it, expect } from "vitest";
import { findRegressions } from "./monitorRegressions";
import { findingFingerprint } from "./fingerprint";

const v = (category: string, name: string, evidence = "e") => ({ category, name, evidence, severity: category === "Scan Coverage" ? "info" : "medium" });

describe("findRegressions", () => {
  it("returns the findings the previous scan did not have", () => {
    const old = v("Security Headers", "Missing CSP");
    const fresh = v("Cookies", "Missing HttpOnly");
    const prev = new Set([findingFingerprint(old.category, old.name, old.evidence)]);
    expect(findRegressions([old, fresh], prev)).toEqual([fresh]);
  });

  it("does not call a scan note that appears a regression", () => {
    const note = v("Scan Coverage", "Scan started from an error response");
    expect(findRegressions([note], new Set())).toEqual([]);
  });

  it("still reports a real finding that arrives beside a note", () => {
    const note = v("Scan Coverage", "Active security testing was skipped for this scan");
    const real = v("Injection", "Reflected XSS");
    expect(findRegressions([note, real], new Set())).toEqual([real]);
  });

  it("returns nothing when nothing is new", () => {
    const a = v("Security Headers", "Missing CSP");
    expect(findRegressions([a], new Set([findingFingerprint(a.category, a.name, a.evidence)]))).toEqual([]);
  });
});

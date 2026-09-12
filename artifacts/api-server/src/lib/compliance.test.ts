import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  FRAMEWORKS,
  COMPLIANCE_DISCLAIMER,
  controlsForFinding,
  summariseCompliance,
} from "./compliance";

describe("controlsForFinding", () => {
  it("maps a weakness to the controls it is evidence for, keyed on CWE", () => {
    const refs = controlsForFinding({ cweId: "CWE-79", category: "Injection" });
    expect(refs.map((r) => `${r.framework}:${r.control}`)).toContain("asvs:V5.3.3");
    expect(refs.map((r) => `${r.framework}:${r.control}`)).toContain("pci:6.2.4");
  });

  it("prefers the CWE mapping over the coarser category mapping", () => {
    // CWE-1104 (unmaintained dependency) is more specific than the category.
    const refs = controlsForFinding({ cweId: "CWE-1104", category: "Network Exposure" });
    expect(refs.some((r) => r.control === "V14.2.1")).toBe(true);
    expect(refs.some((r) => r.control === "1.4.1")).toBe(false);
  });

  it("falls back to category when a finding carries no CWE", () => {
    const refs = controlsForFinding({ cweId: null, category: "Network Exposure" });
    expect(refs.some((r) => r.control === "1.4.1")).toBe(true);
  });

  // An empty list is the honest answer. Inventing a control reference to fill a
  // column is how a report fails the first thing an auditor spot-checks.
  it("returns nothing rather than guessing when neither key maps", () => {
    expect(controlsForFinding({ cweId: "CWE-99999", category: "Technology Fingerprint" })).toEqual([]);
    expect(controlsForFinding({})).toEqual([]);
  });

  it("never emits a control for a framework it does not know", () => {
    for (const cwe of ["CWE-79", "CWE-798", "CWE-319", "CWE-284", "CWE-200"]) {
      for (const ref of controlsForFinding({ cweId: cwe })) {
        expect(FRAMEWORKS[ref.framework]).toBeDefined();
      }
    }
  });
});

describe("summariseCompliance", () => {
  it("counts findings per control and orders the heaviest first", () => {
    const summary = summariseCompliance([
      { cweId: "CWE-79" }, { cweId: "CWE-79" }, { cweId: "CWE-89" },
    ]);
    const asvs = summary.find((s) => s.framework.id === "asvs")!;
    expect(asvs.controls[0]!.control).toBe("V5.3.3");
    expect(asvs.controls[0]!.findings).toBe(2);
  });

  it("omits a framework entirely when nothing mapped to it", () => {
    // CWE-205 maps only to ASVS, so PCI must not appear at all rather than
    // appearing with zero controls, which would read as "assessed and clean".
    const summary = summariseCompliance([{ cweId: "CWE-205" }]);
    expect(summary.some((s) => s.framework.id === "pci")).toBe(false);
  });

  it("returns an empty summary for a clean scan", () => {
    expect(summariseCompliance([])).toEqual([]);
  });

  // THE most important property in this file. A percentage needs a denominator
  // of the framework's full control set, most of which no scan can assess — so
  // any number derived that way is fabricated and reads as an audit score.
  it("reports no pass rate, score or percentage anywhere", () => {
    const summary = summariseCompliance([{ cweId: "CWE-79" }, { cweId: "CWE-319" }]);
    const serialised = JSON.stringify(summary);
    expect(serialised).not.toMatch(/percent|passRate|pass_rate|score|compliant|%/i);
    for (const fw of summary) {
      for (const c of fw.controls) {
        expect(Object.keys(c).sort()).toEqual(["control", "findings", "title"]);
      }
    }
  });
});

describe("honesty guarantees", () => {
  it("every framework states its pinned version, so a control ref is checkable", () => {
    for (const fw of Object.values(FRAMEWORKS)) {
      expect(fw.version.trim().length).toBeGreaterThan(0);
      expect(fw.note.trim().length).toBeGreaterThan(0);
    }
  });

  // Removing this has to be a visible, deliberate act.
  it("the disclaimer refuses the four claims that would be false", () => {
    expect(COMPLIANCE_DISCLAIMER).toMatch(/not a compliance assessment|not an audit/i);
    expect(COMPLIANCE_DISCLAIMER).toMatch(/clean scan is not a passed control/i);
    expect(COMPLIANCE_DISCLAIMER).toMatch(/CPA/);
    expect(COMPLIANCE_DISCLAIMER).toMatch(/QSA/);
  });

  it("PCI's note says this is not an ASV scan", () => {
    // Requirement 11.3.2 needs an Approved Scanning Vendor. Letting a customer
    // believe this satisfies it would be the single most damaging thing the
    // mapping could imply.
    expect(FRAMEWORKS.pci!.note).toMatch(/not an ASV scan/i);
  });

  it("SOC 2's note says most criteria are outside what a scan can see", () => {
    expect(FRAMEWORKS.soc2!.note).toMatch(/no scan can observe|policy, personnel/i);
  });
});

describe("coverage against the CWEs the scanner actually emits", () => {
  // The mapping is hand-maintained; the scanner's CWEs are assigned per-check by
  // whoever wrote the check. Without this, a new check ships with a CWE nothing
  // maps and its findings silently vanish from the compliance view — the exact
  // drift that bit CAMEL_COLUMNS.
  const libDir = path.join(process.cwd(), "src", "lib");
  const emitted = new Set<string>();
  for (const file of fs.readdirSync(libDir)) {
    if (!file.endsWith(".ts") || file.endsWith(".test.ts")) continue;
    const src = fs.readFileSync(path.join(libDir, file), "utf-8");
    for (const m of src.matchAll(/cweId:\s*"(CWE-\d+)"/g)) emitted.add(m[1]!);
  }

  it("found the scanner's CWE set to check against", () => {
    expect(emitted.size).toBeGreaterThan(40);
  });

  it("maps every CWE the scanner can emit", () => {
    const unmapped = [...emitted].filter((c) => controlsForFinding({ cweId: c }).length === 0).sort();
    expect(unmapped).toEqual([]);
  });
});

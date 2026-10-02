import { describe, it, expect } from "vitest";
import { isScanNote, splitScanNotes } from "./scanNotes";

describe("scan notes", () => {
  it("knows a note by its category", () => {
    expect(isScanNote({ category: "Scan Coverage", severity: "info" })).toBe(true);
    expect(isScanNote({ category: "Security Headers", severity: "info" })).toBe(false);
  });

  it("treats anything that is not an object of that category as a finding", () => {
    for (const v of [null, undefined, 5, "Scan Coverage", {}]) expect(isScanNote(v)).toBe(false);
  });

  it("splits a list in order", () => {
    const a = { name: "a", category: "x" };
    const n1 = { name: "n1", category: "Scan Coverage" };
    const b = { name: "b", category: "y" };
    const n2 = { name: "n2", category: "Scan Coverage" };
    expect(splitScanNotes([a, n1, b, n2])).toEqual({ findings: [a, b], notes: [n1, n2] });
  });
});

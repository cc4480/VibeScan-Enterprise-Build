import { describe, it, expect } from "vitest";
import { hasFindingActions, isScanNote, splitScanNotes, scanNotesCount, scanNotesMarkdown, NO_FINDINGS_WITH_NOTES, SCAN_NOTES_BLURB, SCAN_NOTES_TITLE } from "./scan-notes";

const v = (id: string, category: string) => ({ id, category });

describe("isScanNote", () => {
  it("is true for the scanner's own category and for nothing else", () => {
    expect(isScanNote({ category: "Scan Coverage" })).toBe(true);
    expect(isScanNote({ category: "Security Headers" })).toBe(false);
    expect(isScanNote({ category: "scan coverage" })).toBe(false);
    expect(isScanNote({ category: "" })).toBe(false);
  });
});

describe("splitScanNotes", () => {
  it("keeps the scan's notes apart from the findings and each list in its own order", () => {
    const list = [v("a", "Injection"), v("n1", "Scan Coverage"), v("b", "Security Headers"), v("n2", "Scan Coverage"), v("c", "Exposure")];
    const { findings, notes } = splitScanNotes(list);
    expect(findings.map((x) => x.id)).toEqual(["a", "b", "c"]);
    expect(notes.map((x) => x.id)).toEqual(["n1", "n2"]);
  });

  it("loses nothing: every item lands in exactly one list", () => {
    const list = [v("1", "Scan Coverage"), v("2", "X"), v("3", "Scan Coverage"), v("4", "Y")];
    const { findings, notes } = splitScanNotes(list);
    expect(findings.length + notes.length).toBe(list.length);
    expect([...findings, ...notes].map((x) => x.id).sort()).toEqual(["1", "2", "3", "4"]);
  });

  it("handles an empty list, a list of only findings and a list of only notes", () => {
    expect(splitScanNotes([])).toEqual({ findings: [], notes: [] });
    expect(splitScanNotes([v("a", "X")])).toEqual({ findings: [v("a", "X")], notes: [] });
    expect(splitScanNotes([v("n", "Scan Coverage")])).toEqual({ findings: [], notes: [v("n", "Scan Coverage")] });
  });

  it("does not change the list it was given", () => {
    const list = Object.freeze([v("a", "X"), v("n", "Scan Coverage")]);
    expect(() => splitScanNotes(list)).not.toThrow();
    expect(list).toHaveLength(2);
  });

  it("keeps whatever else the items carry", () => {
    const { notes } = splitScanNotes([{ id: "n", category: "Scan Coverage", severity: "info", confidence: 95 }]);
    expect(notes[0]).toEqual({ id: "n", category: "Scan Coverage", severity: "info", confidence: 95 });
  });
});

describe("the words", () => {
  it("counts notes with the right plural", () => {
    expect(scanNotesCount(0)).toBe("0 notes");
    expect(scanNotesCount(1)).toBe("1 note");
    expect(scanNotesCount(2)).toBe("2 notes");
  });

  it("does not call a scan with notes and no findings clean, and points at the notes", () => {
    expect(NO_FINDINGS_WITH_NOTES.title).not.toMatch(/clean|nothing found|no issues/i);
    expect(NO_FINDINGS_WITH_NOTES.body).toContain(SCAN_NOTES_TITLE);
    expect(NO_FINDINGS_WITH_NOTES.body).toMatch(/could not check/);
  });
});

describe("scanNotesMarkdown", () => {
  const note = (id: string) => ({ id, category: "Scan Coverage" });
  const fmt = (n: { id: string }, i: number) => `#### ${i}. ${n.id}`;

  it("writes nothing when there are no notes, whether or not there are findings", () => {
    expect(scanNotesMarkdown([], true, fmt)).toEqual([]);
    expect(scanNotesMarkdown([], false, fmt)).toEqual([]);
  });

  it("writes a counted section with the blurb and each note numbered from one, after the findings", () => {
    const text = scanNotesMarkdown([note("a"), note("b")], true, fmt).join("\n");
    expect(text).toContain(`## ℹ️ ${SCAN_NOTES_TITLE} (2)`);
    expect(text).toContain(`> ${SCAN_NOTES_BLURB}`);
    expect(text.indexOf("#### 1. a")).toBeLessThan(text.indexOf("#### 2. b"));
    expect(text).not.toContain(NO_FINDINGS_WITH_NOTES.title);
  });

  it("leads with 'No findings were reported' when the report has no findings, so a pasted copy is not read as clean", () => {
    const text = scanNotesMarkdown([note("a")], false, fmt).join("\n");
    expect(text.indexOf(NO_FINDINGS_WITH_NOTES.title)).toBeGreaterThanOrEqual(0);
    expect(text.indexOf(NO_FINDINGS_WITH_NOTES.title)).toBeLessThan(text.indexOf(SCAN_NOTES_TITLE + " ("));
    expect(text).toContain(NO_FINDINGS_WITH_NOTES.body);
  });

  it("is a list of lines that ends on a blank line, like the other sections, so the next heading is separated", () => {
    const lines = scanNotesMarkdown([note("a")], true, fmt);
    expect(lines[lines.length - 1]).toBe("");
  });
});

describe("hasFindingActions", () => {
  it("offers 'Check my fix' and 'Mark as false positive' on a finding and not on a scan note", () => {
    expect(hasFindingActions({ category: "Security Headers" })).toBe(true);
    expect(hasFindingActions({ category: "Scan Coverage" })).toBe(false);
  });
});

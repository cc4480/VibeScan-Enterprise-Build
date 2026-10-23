import { describe, it, expect } from "vitest";
import { changeGroups, hasChanges, headline, shortDate, unchangedSentence, type ScanChanges } from "./report-changes";

const f = (name: string, severity = "high") => ({ name, severity, category: "HTTP Security" });
const base: ScanChanges = { since: { scanId: "s0", scannedAt: "2026-09-20T10:00:00.000Z" }, unchanged: 0, added: [], firstSeen: [], fixed: [], notRechecked: [], newlyRun: [], noLongerRun: [], differentAccess: false };

describe("changeGroups", () => {
  it("shows only the groups that have something, worst news first", () => {
    const groups = changeGroups({ ...base, added: [f("a")], fixed: [f("b"), f("c")] });
    expect(groups.map((g) => [g.key, g.label])).toEqual([["new", "1 new"], ["fixed", "2 fixed"]]);
  });

  it("never lets 'not re-checked' pass for 'fixed': it says so in words", () => {
    const [g] = changeGroups({ ...base, notRechecked: [f("a")] });
    expect(g!.tone).toBe("neutral");
    expect(g!.note).toContain("not the same as fixed");
  });

  it("says a first-seen finding may have been there all along", () => {
    const [g] = changeGroups({ ...base, firstSeen: [f("a")] });
    expect(g!.note).toContain("may have been there all along");
  });

  it("says why a fix is a fix", () => {
    expect(changeGroups({ ...base, fixed: [f("a")] })[0]!.note).toContain("ran again");
  });

  it("is empty when nothing changed", () => {
    expect(changeGroups(base)).toEqual([]);
  });
});

describe("hasChanges", () => {
  it("is true for any group, for newly run tests, and for a different login", () => {
    expect(hasChanges({ ...base, added: [f("a")] })).toBe(true);
    expect(hasChanges({ ...base, newlyRun: ["active CORS"] })).toBe(true);
    expect(hasChanges({ ...base, differentAccess: true })).toBe(true);
    expect(hasChanges(base)).toBe(false);
  });
});

describe("wording", () => {
  it("dates the comparison the same way on every machine", () => {
    expect(shortDate("2026-09-20T10:00:00.000Z")).toBe("20 Sep");
    expect(headline(base)).toBe("Since your last scan (20 Sep)");
    expect(headline({ ...base, since: { scanId: null, scannedAt: null } })).toBe("Since your last scan");
    expect(shortDate("garbage")).toBeNull();
  });

  it("says plainly when nothing changed", () => {
    expect(unchangedSentence({ ...base, unchanged: 3 })).toBe("Nothing new and nothing fixed. 3 findings carried over.");
    expect(unchangedSentence({ ...base, unchanged: 1 })).toContain("1 finding carried over");
    expect(unchangedSentence(base)).toBe("Nothing found either time.");
  });
});

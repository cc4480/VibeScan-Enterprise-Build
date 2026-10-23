import { describe, it, expect } from "vitest";
import {
  fixedFindingIds,
  fixedNotice,
  latestFixDate,
  outdatedAnalysisNote,
  subtractFixed,
} from "./fixed-findings.js";
import type { VerificationStatus } from "./verify-fix.js";

const v = (findingId: string, verdict: VerificationStatus["verdict"], createdAt: string, completedAt: string | null = createdAt): VerificationStatus => ({
  findingId,
  verdict,
  scanId: "s",
  createdAt,
  completedAt,
});

describe("fixedFindingIds", () => {
  it("includes findings whose re-check says fixed", () => {
    expect(fixedFindingIds([v("a", "fixed", "2026-10-12T10:00:00Z")])).toEqual(new Set(["a"]));
  });

  it("never treats the other verdicts as fixed", () => {
    const list = [
      v("a", "pending", "2026-10-12T10:00:00Z", null),
      v("b", "still_present", "2026-10-12T10:00:00Z"),
      v("c", "not_rechecked", "2026-10-12T10:00:00Z"),
      v("d", "failed", "2026-10-12T10:00:00Z"),
    ];
    expect(fixedFindingIds(list).size).toBe(0);
  });

  it("uses the latest re-check when a finding was checked more than once", () => {
    const fixedThenBack = [v("a", "fixed", "2026-10-12T10:00:00Z"), v("a", "still_present", "2026-10-13T10:00:00Z")];
    expect(fixedFindingIds(fixedThenBack).has("a")).toBe(false);
    const backThenFixed = [v("a", "still_present", "2026-10-12T10:00:00Z"), v("a", "fixed", "2026-10-13T10:00:00Z")];
    expect(fixedFindingIds(backThenFixed).has("a")).toBe(true);
  });

  it("copes with no data", () => {
    expect(fixedFindingIds(undefined).size).toBe(0);
    expect(fixedFindingIds([]).size).toBe(0);
  });
});

describe("latestFixDate", () => {
  it("returns the most recent verified fix", () => {
    const list = [v("a", "fixed", "2026-10-10T10:00:00Z"), v("b", "fixed", "2026-10-12T09:00:00Z"), v("c", "still_present", "2026-10-13T09:00:00Z")];
    expect(latestFixDate(list)).toBe("2026-10-12T09:00:00Z");
  });

  it("is null when nothing is fixed", () => {
    expect(latestFixDate([v("a", "still_present", "2026-10-12T10:00:00Z")])).toBeNull();
    expect(latestFixDate(undefined)).toBeNull();
  });
});

describe("subtractFixed", () => {
  const counts = { critical: 0, high: 1, medium: 1, low: 2, info: 1 };

  it("takes each fixed finding out of its severity", () => {
    expect(subtractFixed(counts, [{ severity: "medium" }, { severity: "low" }])).toEqual({ critical: 0, high: 1, medium: 0, low: 1, info: 1 });
  });

  it("never goes below zero and ignores unknown severities", () => {
    expect(subtractFixed(counts, [{ severity: "critical" }, { severity: "bogus" }])).toEqual(counts);
  });

  it("does not change the object it was given", () => {
    const before = { ...counts };
    subtractFixed(counts, [{ severity: "high" }]);
    expect(counts).toEqual(before);
  });
});

describe("notices", () => {
  it("says what changed and what did not", () => {
    expect(fixedNotice(1, "2026-10-12T10:00:00Z")).toBe(
      "1 finding verified fixed since this scan (12 Oct). The grade and the AI analysis describe the scan as it ran.",
    );
    expect(fixedNotice(2, null)).toContain("2 findings verified fixed since this scan.");
  });

  it("shows nothing when nothing is fixed", () => {
    expect(fixedNotice(0, null)).toBeNull();
    expect(outdatedAnalysisNote(0)).toBeNull();
  });

  it("warns that the analysis was written before the fixes", () => {
    expect(outdatedAnalysisNote(1)).toBe("Written when the scan ran. 1 finding has since been verified fixed, so parts of this may no longer apply.");
    expect(outdatedAnalysisNote(3)).toContain("3 findings have since been verified fixed");
  });
});

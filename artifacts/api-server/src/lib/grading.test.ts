import { describe, it, expect } from "vitest";
import { computeGrade, gradeForResult, GRADE_INCOMPLETE, computeRiskScore } from "./scanner.js";

describe("gradeForResult refuses to grade an intercepted scan", () => {
  it("grades a normal scan by its score", () => {
    expect(gradeForResult(0, false)).toBe("A");
    expect(gradeForResult(30, false)).toBe("C");
    expect(gradeForResult(100, false)).toBe("F");
  });

  it("returns the incomplete sentinel when intercepted, whatever the score", () => {
    // The whole point: a challenge-answered scan scores 0 because every
    // deducting finding was withheld, so computeGrade would call it A. It must
    // not. This is the inversion the false-positive audit kept catching — an
    // interstitial's silence read as the target's merit.
    expect(gradeForResult(0, true)).toBe(GRADE_INCOMPLETE);
    expect(computeGrade(0)).toBe("A"); // and this is exactly what we are avoiding
    expect(GRADE_INCOMPLETE).not.toMatch(/^[A-F]$/);
  });

  it("the withheld finding set really does score 0", () => {
    // Mirrors reality: after withholding, only info-severity coverage notes
    // remain, and info weighs 0 in computeRiskScore.
    const withheld = [
      { severity: "info" } as never,
      { severity: "info" } as never,
    ];
    expect(computeRiskScore(withheld)).toBe(0);
    expect(gradeForResult(computeRiskScore(withheld), true)).toBe(GRADE_INCOMPLETE);
  });
});

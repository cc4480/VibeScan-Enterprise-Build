import type { ScanVulnerability } from "./scannerTypes";

export function computeRiskScore(vulns: ScanVulnerability[]): number {
  let score = 0;
  for (const v of vulns) {
    switch (v.severity) {
      case "critical": score += 30; break;
      case "high":     score += 15; break;
      case "medium":   score += 5;  break;
      case "low":      score += 1;  break;
      case "info":     score += 0;  break;
    }
  }
  return Math.min(score, 100);
}

export function computeGrade(riskScore: number): string {
  if (riskScore <= 10) return "A";
  if (riskScore <= 25) return "B";
  if (riskScore <= 45) return "C";
  if (riskScore <= 65) return "D";
  return "F";
}

/**
 * The grade sentinel for a scan that must not be graded at all.
 *
 * A bot-protection layer that answers instead of the origin drives
 * computeRiskScore to 0 — the best score — because every finding that could
 * deduct was withheld, not because the site is clean. Grading it A is the exact
 * inversion the false-positive audit kept catching: an interstitial's silence
 * read as the target's merit. The report and dashboard render this value as
 * "coverage incomplete".
 */
export const GRADE_INCOMPLETE = "N/A";

/** computeGrade, except an intercepted scan yields the incomplete sentinel. */
export function gradeForResult(riskScore: number, intercepted: boolean): string {
  return intercepted ? GRADE_INCOMPLETE : computeGrade(riskScore);
}

/** The one-paragraph summary at the top of a report, from its grade, score and finding counts. */
export function buildExecutiveSummary(
  grade: string,
  riskScore: number,
  targetUrl: string,
  totalVulns: number,
  counts: Record<string, number>,
): string {
  const domain = (() => {
    try { return new URL(targetUrl).hostname; } catch { return targetUrl; }
  })();

  const critical = counts["critical"] ?? 0;
  const high = counts["high"] ?? 0;

  if (totalVulns === 0) {
    // Not "passed all security checks": a scan with skipped tests has not checked those areas,
    // and a clean grade says nothing about them. The report's coverage section lists them.
    return `${domain} has a grade of ${grade}: the tests that ran found no significant vulnerabilities. That is not a statement about any area this scan did not test, which the report lists. Re-scan regularly.`;
  }

  const urgencyPhrase =
    critical > 0
      ? `${critical} critical issue${critical > 1 ? "s" : ""} requiring immediate attention`
      : high > 0
        ? `${high} high-severity issue${high > 1 ? "s" : ""} that should be addressed promptly`
        : `${totalVulns} security finding${totalVulns > 1 ? "s" : ""}, none of them critical or high`;
  const advice = critical + high > 0 ? " Review the findings below and fix the critical and high items first." : "";

  return `Security scan of ${domain} identified ${urgencyPhrase}, yielding an overall grade of ${grade} with a risk score of ${riskScore}/100.${advice}`;
}

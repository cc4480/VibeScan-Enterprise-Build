/**
 * Which OWASP Top 10 categories a scan actually tested.
 *
 * The OWASP card used to count a category as "passed" whenever no finding mapped to it. That
 * is not the same thing: a category with no findings and no test is a category nobody looked
 * at. A scan without verified ownership skips every active test, and the card still ticked
 * "Broken Access Control" and "Injection" green, next to a summary saying the access-control
 * tests "were skipped and remain unchecked".
 *
 * A category is now only "clear" when the tests that speak to it ran and found nothing.
 * The mapping is by test name (see the ledger in api-server/src/lib/testLedger.ts and the
 * families named in scanner.ts). It is a judgement about coverage, not a proof of it, which
 * is why the card says "clear" and never "secure".
 */

export type OwaspState =
  /** At least one finding maps here. */
  | "flagged"
  /** No findings, and every test that covers this category ran. */
  | "clear"
  /** No findings, but some of the tests that cover it were skipped or failed. */
  | "partial"
  /** No findings, and none of the tests that cover it ran (or none exist). */
  | "untested"
  /** No findings, and the scan kept no test record, so nothing can be said. */
  | "unknown";

export interface TestLike {
  name: string;
  status: "ran" | "skipped" | "failed";
}

/** The recorded tests that speak to each category. */
export const OWASP_TESTS: Record<string, RegExp> = {
  A01: /cross-account access|API endpoint testing|path traversal|Supabase RLS|BaaS open data|public cloud storage|GraphQL/i,
  A02: /TLS configuration|SSL Labs|mail transport|HTTP probes/i,
  A03: /^injection|API endpoint testing|GraphQL/i,
  A05: /HTTP probes|exposed API documentation|source map|Next\.js|public cloud storage|subdomain takeover|DNS and email/i,
  A06: /known-CVE|dependency CVEs/i,
  A07: /JWT analysis|API endpoint testing|cross-account access|HTTP probes/i,
  A08: /JavaScript secret scanning|Next\.js|HTTP probes/i,
};

export interface OwaspCoverage {
  state: OwaspState;
  /** Covering tests that did not run, for the tooltip. */
  notRun: string[];
}

export function owaspCoverage(code: string, findings: number, tests?: TestLike[] | null): OwaspCoverage {
  if (findings > 0) return { state: "flagged", notRun: [] };
  const list = Array.isArray(tests) ? tests.filter((t) => t && typeof t.name === "string") : [];
  if (list.length === 0) return { state: "unknown", notRun: [] };

  const match = OWASP_TESTS[code];
  const relevant = match ? list.filter((t) => match.test(t.name)) : [];
  if (relevant.length === 0) return { state: "untested", notRun: [] };

  const notRun = relevant.filter((t) => t.status !== "ran").map((t) => t.name);
  if (notRun.length === relevant.length) return { state: "untested", notRun };
  return { state: notRun.length > 0 ? "partial" : "clear", notRun };
}

/**
 * Findings per OWASP code, split into those that need action and informational notes. Only the
 * first flag a category: a lone "COEP header not set" (info) marked Security Misconfiguration red
 * on an otherwise clean, A-graded report, which told the reader there was a problem the finding
 * itself says there is not.
 */
export function owaspFindingCounts(
  vulns: { category: string; severity: string }[],
): Record<string, { actionable: number; info: number }> {
  const out: Record<string, { actionable: number; info: number }> = {};
  for (const v of vulns) {
    for (const code of CATEGORY_TO_OWASP[v.category] ?? []) {
      const c = (out[code] ??= { actionable: 0, info: 0 });
      if (v.severity === "info") c.info += 1;
      else c.actionable += 1;
    }
  }
  return out;
}

/** Which OWASP Top 10 codes a finding category speaks to. */
export const CATEGORY_TO_OWASP: Record<string, string[]> = {
  "Transport Security":             ["A02"],
  "Injection Defense":              ["A03"],
  "Injection":                      ["A03"],
  "UI Security":                    ["A05"],
  "Content Sniffing":               ["A05"],
  "Information Disclosure":         ["A05"],
  "Browser Feature Control":        ["A05"],
  "CORS Misconfiguration":          ["A05"],
  "Session Management":             ["A02", "A07"],
  "CSRF Protection":                ["A07"],
  "Source Code Exposure":           ["A03", "A05"],
  "Credential Exposure":            ["A02"],
  "Data Exposure":                  ["A01"],
  "HTTP Security":                  ["A05"],
  "Unvalidated Redirects":          ["A01"],
  "Supply Chain Security":          ["A06", "A08"],
  "Brute Force Protection":         ["A07"],
  "Email Security":                 ["A05"],
  "DNS Security":                   ["A05"],
  "Exposed Secrets / Credentials":  ["A02"],
  "Security Header Inconsistency":  ["A05"],
  "Outdated Software / Known CVE":  ["A06"],
  "Outdated Software":              ["A06"],
  "Network Exposure":               ["A01"],
};

export const OWASP_CATEGORIES: Array<{ code: string; name: string }> = [
  { code: "A01", name: "Broken Access Control" },
  { code: "A02", name: "Cryptographic Failures" },
  { code: "A03", name: "Injection" },
  { code: "A05", name: "Security Misconfiguration" },
  { code: "A06", name: "Vulnerable Components" },
  { code: "A07", name: "Auth & Session Failures" },
  { code: "A08", name: "Data Integrity Failures" },
];

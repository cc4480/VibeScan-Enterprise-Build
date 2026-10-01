/**
 * "How this was found", for one finding: which check raised it, whether that check only read what
 * the site sends every visitor or sent test requests, and the requests the evidence records.
 *
 * Everything here comes from the stored report: the check is the test record whose `found` list
 * names the finding, and the requests are lines the scanner wrote into the evidence. Nothing is
 * reconstructed; when the report does not say, this says "not recorded" rather than guessing.
 */

export interface ProvenanceTest {
  group: string;
  name: string;
  status: "ran" | "skipped" | "failed";
  found?: string[];
}

export interface Provenance {
  /** The check that raised the finding, when the report recorded it. */
  check: string | null;
  kind: "active" | "observation" | "scan note" | "unknown";
  /** Request lines from the evidence, e.g. "GET https://x.test/.env → HTTP 200". At most five. */
  requests: string[];
}

const REQUEST_RE = /^\s*(?:\[[^\]]*\]\s+)?(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+(?:https?:\/\/|\/)\S*/;

/** Test groups whose checks send attack-shaped or state-probing requests. */
const ACTIVE_GROUPS = new Set(["active"]);
/** Active checks the scanner records under its "HTTP probes" group (probes.ts). */
const ACTIVE_HTTP_PROBES = new Set(["HTTP methods", "active CORS", "open redirect", "Supabase RLS"]);

export function findingProvenance(
  finding: { name: string; category: string; evidence?: string | null },
  tests: ProvenanceTest[] | null | undefined,
): Provenance {
  const requests = (finding.evidence ?? "")
    .split(/\r?\n/)
    .filter((l) => REQUEST_RE.test(l))
    .map((l) => l.trim())
    .slice(0, 5);

  if (finding.category === "Scan Coverage") return { check: null, kind: "scan note", requests };

  const test = (tests ?? []).find((t) => Array.isArray(t.found) && t.found.includes(finding.name));
  if (!test) return { check: null, kind: "unknown", requests };
  return {
    check: test.name,
    kind: ACTIVE_GROUPS.has(test.group.toLowerCase()) || ACTIVE_HTTP_PROBES.has(test.name) ? "active" : "observation",
    requests,
  };
}

export const PROVENANCE_KIND_TEXT: Record<Provenance["kind"], string> = {
  active: "Active test: the scanner sent test requests to your site and judged the replies.",
  observation:
    "Observation: the scanner read what your site sends to any visitor (its pages, headers and a few well-known paths). No attack traffic was involved.",
  "scan note": "A note about the scan itself, not a finding about your site.",
  unknown: "Which check raised this was not recorded for this report.",
};

/** What a confidence number means, in one sentence. */
export function confidenceText(confidence: number | null | undefined): string | null {
  if (confidence == null) return null;
  if (confidence >= 85) return `${confidence}% confidence: seen directly in your site's response.`;
  if (confidence >= 55) return `${confidence}% confidence: inferred from your site's response. Worth confirming by hand.`;
  return `${confidence}% confidence: a weak signal. Confirm by hand before acting.`;
}

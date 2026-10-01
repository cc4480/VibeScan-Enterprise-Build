import { testEndpoint, type ApiProbeHits } from "./apiProbeEndpoint";
import { buildApiFindings } from "./apiProbeFindings";
import type { ScanVulnerability } from "./scanner";
import { isDestructiveUrl } from "./destructive";
import { sameIdentity } from "./accessControlCompare";
import { MAX_ENDPOINTS_TESTED, concreteUrl, isReadShaped, isHandlerReached, type ApiProbeInput, exposedSensitiveFields, privilegeFieldsAccepted } from "./apiProbeHelpers";

/**
 * Security testing against a discovered API surface.
 *
 * lib/apiSurface.ts recovers the endpoints; this decides what is safe to ask
 * them. Two checks, both aimed at the failures that dominate the OWASP API
 * Security Top 10:
 *
 *   1. Missing authentication — an endpoint that answers a caller with no
 *      session at all. On an API-first app this is where data actually leaks,
 *      and it is invisible to an HTML-shaped scan.
 *   2. SQL injection in API parameters — query, path, and JSON body fields the
 *      spec declares, which no HTML form ever exposes.
 *
 * ── Safety ──────────────────────────────────────────────────────────────────
 *
 * This runs against a live application belonging to a paying customer, so the
 * rule is: never send a request whose *success* would change their data.
 *
 *   - Only GET and HEAD are ever issued for auth coverage. A POST sent without
 *     a session to check whether it is rejected would perform the write if the
 *     answer is "no", which is exactly the case worth reporting — the test
 *     would cause the damage it is meant to warn about.
 *   - Body injection is restricted to read-shaped endpoints (search, query,
 *     filter, report, graphql). A POST /orders carrying a quote is an order.
 *   - The destructive-URL guard applies throughout.
 *
 * The cost is real and worth stating: write-endpoint authorisation is not
 * covered here. That needs a target the customer has told us is disposable,
 * which is a product decision rather than a scanner one.
 */









export { concreteUrl, isReadShaped, isHandlerReached, jsonFieldNames, exposedSensitiveFields, privilegeFieldsAccepted } from "./apiProbeHelpers";
export { collectApiSurface } from "./apiProbeSurface";
export type { ApiProbeInput } from "./apiProbeHelpers";

export async function runApiProbes(input: ApiProbeInput): Promise<ScanVulnerability[]> {
  const testable = input.endpoints
    .filter((e) => !isDestructiveUrl(concreteUrl(e)))
    .filter(isReadShaped)
    .slice(0, MAX_ENDPOINTS_TESTED);

  // Mass assignment is read from the declared contract and sends nothing, so it is not limited to
  // read-shaped endpoints: the create and signup endpoints isReadShaped leaves out are exactly where
  // a "role" field gets bound onto a new record.
  // Outside the read-shaped set, only a published spec counts: a field the app's own front end sends
  // (user_id on a comment, plan on a checkout) is not a declaration that the server binds it.
  const massAssignable = input.endpoints
    .filter((e) => e.source === "spec" || isReadShaped(e))
    .slice(0, MAX_ENDPOINTS_TESTED * 4)
    .map((e) => ({ endpoint: `${e.method} ${new URL(concreteUrl(e)).pathname}`, fields: privilegeFieldsAccepted(e) }))
    .filter((m) => m.fields.length > 0);

  if (testable.length === 0) return buildApiFindings({ ...emptyHits(), massAssignable });
  const unauthorizedWrites: string[] = [];

  // One account presented twice is not two accounts: every "shared" record would be the same
  // user's own. Cross-account comparison is skipped; the single-session checks still run.
  const secondary =
    input.secondary && input.credentials && sameIdentity(input.credentials, input.secondary)
      ? undefined
      : input.secondary;

  const hits: ApiProbeHits = { ...emptyHits(), massAssignable };
  for (const endpoint of testable) await testEndpoint(endpoint, input, secondary, hits);

  return buildApiFindings(hits);
}

function emptyHits(): ApiProbeHits {
  return { unauthenticated: [], injectable: [], overExposed: [], unratelimited: [], crossAccount: [], massAssignable: [], unauthorizedWrites: [] };
}

/**
 * Active race-condition probe (CWE-362) — OFF by default, and gated
 * separately from every other active check in this scanner.
 *
 * Every other active probe (SQLi, XSS, SSTI, IDOR reads, ...) either reads
 * data or sends a payload whose failure mode is "nothing happens". A race
 * condition test is structurally different: proving one exists means firing
 * several concurrent requests at a real "claim this once" action — a coupon
 * redemption, a promo code, a one-time bonus — and if the target genuinely
 * has the bug, this probe causes it to actually fire more than once, for
 * real, against the account under test. There is no way to test for this
 * class of bug without exercising the mutation.
 *
 * Because of that, this requires TWO separate, independent things to be true
 * before it sends a single request:
 *
 *   1. The ordinary active-probe gate (ownership-verified or an operator
 *      override) — same as everything else.
 *   2. `raceConditionTesting: true`, an explicit opt-in passed by the caller
 *      for this scan alone. It is never on by default and never inferred
 *      from tier or plan. A scan that doesn't ask for this cannot get it.
 *
 * Scope is kept as small as the check allows: at most 3 candidate endpoints
 * (URL/action names that read as a one-time claim — "redeem", "coupon",
 * "promo", "claim", "apply-code"), 5 concurrent requests each, using only the
 * scan's own primary test account. That is a maximum of 15 requests, against
 * resources the account under test already has the right to attempt legally
 * — this proves the endpoint has no concurrency control, it never targets
 * another user's data or another account's resource.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch, type ScanCredentials } from "./http";

const MAX_CANDIDATES = 3;
const CONCURRENT_ATTEMPTS = 5;
const TIMEOUT_MS = 8_000;

const CLAIM_ENDPOINT_RE = /\b(redeem|coupon|promo(?:code)?|claim|apply-?code|use-?code|voucher)\b/i;

const ALREADY_USED_RE =
  /\b(already (used|redeemed|claimed|applied)|invalid (code|coupon)|expired|no longer valid|one[- ]time use)\b/i;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

function looksLikeSuccess(status: number, body: string): boolean {
  if (status < 200 || status >= 300) return false;
  return !ALREADY_USED_RE.test(body.slice(0, 2_000));
}

export interface RaceConditionInput {
  /** API endpoints discovered during the crawl. */
  endpoints: string[];
  credentials: ScanCredentials;
}

/**
 * Only called when the caller has already checked BOTH gates described above
 * — this function itself does not re-check the opt-in flag, so callers must
 * not wire it up to run unconditionally.
 */
export async function runRaceConditionProbe(
  input: RaceConditionInput,
): Promise<ScanVulnerability[]> {
  const candidates = [...new Set(input.endpoints)]
    .filter((u) => CLAIM_ENDPOINT_RE.test(u))
    .slice(0, MAX_CANDIDATES);

  const findings: ScanVulnerability[] = [];

  for (const url of candidates) {
    const attempts = await Promise.all(
      Array.from({ length: CONCURRENT_ATTEMPTS }, () =>
        scanFetch(url, {
          method: "POST",
          timeoutMs: TIMEOUT_MS,
          as: input.credentials,
          headers: { "Content-Type": "application/json" },
          body: "{}",
        }),
      ),
    );

    const successes = attempts.filter((r) => r && looksLikeSuccess(r.status, r.body));
    if (successes.length >= 2) {
      findings.push(
        vuln({
          name: "Race Condition Allows a One-Time Action to Succeed Multiple Times",
          severity: "high",
          category: "Business Logic",
          description:
            `${CONCURRENT_ATTEMPTS} identical requests were sent to ${url} at the same time, using the same test ` +
            `account. ${successes.length} of them were accepted as successful, where a correctly built one-time action ` +
            `should accept exactly one and reject the rest. This is a time-of-check-to-time-of-use race condition: the ` +
            `endpoint checks "has this already been used" and performs the action as two separate steps, and concurrent ` +
            `requests can slip between them. Depending on what this endpoint does, this can mean a discount applied ` +
            `repeatedly, a bonus credited more than once, or any other one-time grant claimed many times over.`,
          evidence:
            `POST ${url}, ${CONCURRENT_ATTEMPTS} concurrent requests, same account, empty JSON body.\n` +
            `${successes.length} of ${CONCURRENT_ATTEMPTS} returned a success-shaped response.`,
          solution:
            "Make the check-and-use step atomic at the database: a single UPDATE ... WHERE used = false (or an " +
            "equivalent conditional write / unique constraint) so only one concurrent request can win, rather than a " +
            "separate SELECT to check followed by an UPDATE to apply. A short-lived lock or a serializable transaction " +
            "around the whole operation works as well; a plain read-then-write does not.",
          cweId: "CWE-362",
          cvssScore: 6.5,
          wstgId: "WSTG-BUSL-03",
          confidence: 90,
        }),
      );
    }
  }

  return findings;
}

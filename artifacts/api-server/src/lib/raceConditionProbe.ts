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
 * (routes whose LAST path segment reads as a one-time claim — redeem, claim,
 * apply-code — see isClaimEndpointUrl), 5 concurrent requests each and ONE
 * request after them, using only the scan's own primary test account: at most
 * 18 requests. Targets are chosen by actingEndpoints.ts: only the scan target,
 * only concrete non-destructive URLs, never a redirect followed.
 *
 * What counts as a race. Five concurrent requests are accepted (at least two of
 * them) AND a sixth, sent after they have all finished, is refused with a reply that says the
 * action was already used (oneTimeReply.isSpentReply). That is the shape of check-then-act: the endpoint does enforce "once", but the
 * check and the write are two steps and concurrent requests slip between them.
 * An endpoint that also accepts the sixth has no limit at all or is idempotent
 * ("apply this code to my cart"), which this probe cannot tell apart and does not
 * call a race; one whose sixth reply is a rate limit, a WAF's 403, an outage or any refusal that does not say
 * "already used" proves nothing either way. What each reply MEANS is read by oneTimeReply.ts, since a 200 is
 * often a refusal in the body.
 *
 * And it says when it tested nothing: the body is always `{}`, so a real redeem
 * route that needs a code answers 400 five times, and only body-less claims can
 * be tested at all. Those outcomes return `notTested` so the ledger records a
 * skip rather than a clean run.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch, type ScanCredentials } from "./http";
import { actableEndpoints, pathLeaf, type EndpointInput } from "./actingEndpoints";
import { classifyReply, isSpentReply } from "./oneTimeReply";
import type { ProbeOutcome } from "./testLedger";

const MAX_CANDIDATES = 3;
const CONCURRENT_ATTEMPTS = 5;
const TIMEOUT_MS = 8_000;

/** Last path segments that are a claim on their own (normalised: lower case, no - or _). */
const CLAIM_LEAVES = new Set([
  "redeem", "redeemcode", "redeemcoupon", "redeemvoucher", "redeempromo", "applycode", "applycoupon",
  "applypromo", "applypromocode", "usecode", "usecoupon", "claim", "claimreward", "claimbonus",
  "claimcode", "claimcoupon", "promocode", "couponcode",
]);
/** Leaves that mean a one-time claim only under a parent that names what is being claimed. */
const CLAIM_PARENT_LEAVES = new Set(["redeem", "apply", "claim", "use", "submit", "activate"]);
const CLAIM_PARENTS = new Set([
  "coupon", "coupons", "promo", "promos", "promocode", "promocodes", "voucher", "vouchers", "reward", "rewards",
  "bonus", "bonuses", "giftcard", "giftcards", "referral", "referrals", "code", "codes", "claim", "claims",
]);

/**
 * Is this URL a one-time claim? Decided by the last path segment, never by the host and never by a
 * word somewhere in the path: https://promo.acme.com/api/account/delete is not a claim, and neither
 * is /api/coupon/validate (an idempotent lookup) or /api/coupons (a collection; a POST creates one).
 */
export function isClaimEndpointUrl(url: string): boolean {
  const { leaf, parent } = pathLeaf(url);
  return CLAIM_LEAVES.has(leaf) || (CLAIM_PARENT_LEAVES.has(leaf) && CLAIM_PARENTS.has(parent));
}

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

export interface RaceConditionInput {
  /** API endpoints discovered during the crawl: plain URLs, or the discovery records with method. */
  endpoints: EndpointInput[];
  credentials: ScanCredentials;
  /** Per-request timeout, covering the reply body. Tests shorten it. */
  timeoutMs?: number;
}

/**
 * Only called when the caller has already checked BOTH gates described above
 * — this function itself does not re-check the opt-in flag, so callers must
 * not wire it up to run unconditionally.
 */
export async function runRaceConditionProbe(input: RaceConditionInput): Promise<ScanVulnerability[]> {
  return (await runRaceConditionProbeDetailed(input)).findings;
}

/** The findings, and — when nothing was actually exercised — why not. */
export async function runRaceConditionProbeDetailed(input: RaceConditionInput): Promise<ProbeOutcome> {
  const candidates = actableEndpoints(input.endpoints, isClaimEndpointUrl).slice(0, MAX_CANDIDATES);
  if (candidates.length === 0) {
    return { findings: [], notTested: "no claim-style endpoint (redeem, claim, apply-code) was found that the scan could safely send requests to" };
  }

  const timeoutMs = input.timeoutMs ?? TIMEOUT_MS;
  const post = (url: string) =>
    scanFetch(url, {
      method: "POST",
      timeoutMs,
      as: input.credentials,
      // A redirected POST is not a claim, and following it would carry the request wherever it points.
      redirect: "manual",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });

  const findings: ScanVulnerability[] = [];
  let exercised = 0;
  const refusals: string[] = [];

  for (const { url } of candidates) {
    const burst = await Promise.all(Array.from({ length: CONCURRENT_ATTEMPTS }, () => post(url)));
    const kinds = burst.map(classifyReply);
    const accepted = kinds.filter((k) => k === "accepted").length;
    if (accepted === 0) {
      refusals.push(`${url} (${burst.map((r) => r?.status ?? "no reply").join(", ")})`);
      continue;
    }
    exercised++;
    if (accepted < 2) continue; // exactly one got through: the endpoint held

    // After the burst: a real one-time action is spent by now. If this is accepted too, the
    // endpoint has no limit (or is idempotent), which is not a race. A refusal only counts when it
    // says the action was already used: a rate limiter's or WAF's 403/429, or "invalid code", is a
    // refusal for another reason and proves no one-time rule exists.
    const sixth = await post(url);
    if (!isSpentReply(sixth)) continue;

    findings.push(
      vuln({
        name: "Race Condition Allows a One-Time Action to Succeed Multiple Times",
        severity: "high",
        category: "Business Logic",
        description:
          `${CONCURRENT_ATTEMPTS} identical requests were sent to ${url} at the same time, using the same test ` +
          `account. ${accepted} of them were accepted, where a correctly built one-time action should accept exactly ` +
          `one and reject the rest — and a request sent after they had all finished WAS refused, so the endpoint does ` +
          `enforce "once" but not atomically. This is a time-of-check-to-time-of-use race condition: the endpoint checks ` +
          `"has this already been used" and performs the action as two separate steps, and concurrent requests can slip ` +
          `between them. Depending on what this endpoint does, this can mean a discount applied repeatedly, a bonus ` +
          `credited more than once, or any other one-time grant claimed many times over.`,
        evidence:
          `POST ${url}, ${CONCURRENT_ATTEMPTS} concurrent requests, same account, empty JSON body.\n` +
          `${accepted} of ${CONCURRENT_ATTEMPTS} were accepted (a 2xx whose body does not refuse them).\n` +
          `A sixth request, sent after the others had finished, was refused as already used (${sixth?.status}): ` +
          `${sixth?.body.trim().replace(/\s+/g, " ").slice(0, 120)}`,
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

  if (findings.length === 0 && exercised === 0) {
    return {
      findings: [],
      notTested:
        `no claim endpoint accepted an empty request, so nothing was tested (a redeem route that needs a code cannot be exercised without one): ${refusals.join("; ")}`,
    };
  }
  return { findings };
}

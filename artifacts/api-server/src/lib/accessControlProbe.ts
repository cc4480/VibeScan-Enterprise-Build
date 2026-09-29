/**
 * A01: Broken access control — IDOR / BOLA detection.
 *
 * The top OWASP risk category, and the one a black-box scan cannot touch
 * without credentials: it is not about whether a page is reachable, but about
 * whether the *wrong person* can reach it.
 *
 * The technique is a three-way comparison. For a URL that names a specific
 * record, ask for the very same URL as three different callers:
 *
 *   A — the primary session (the record's owner)
 *   B — a second, separate account
 *   ∅ — nobody at all
 *
 * and compare what comes back.
 *
 *   A ≈ B  and  ∅ denied   → B reads A's record. Broken object-level
 *                            authorisation. This is the finding worth having.
 *   A ≈ ∅                  → the record needs no session at all.
 *   A ≠ B                  → B saw their own data, or was refused. Correct.
 *
 * Why this shape rather than "can B open /dashboard": B legitimately has a
 * dashboard, so reachability proves nothing. Identical *content* at a URL that
 * names one record is what separates a real authorisation failure from a page
 * both users are entitled to see.
 *
 * The anonymous leg is what keeps public pages out of the report. A product
 * page returns the same bytes to everyone, and without checking ∅ that is
 * indistinguishable from a leak.
 *
 * Layout. This file is the orchestration: it picks the candidate URLs, makes
 * the three requests and applies the comparison. The parts with no network in
 * them live beside it and are re-exported from here, so every import of this
 * module keeps working:
 *
 *   accessControlIdentifiers.ts  which URLs name a record; the neighbours to try
 *   accessControlCompare.ts      content similarity and the denial test
 *   accessControlFindings.ts     the three findings and their wording
 */

import type { ScanVulnerability } from "./scanner";
import { scanFetch, type ScanCredentials } from "./http";
import { isDestructiveUrl } from "./destructive";
import { namesARecord, mutateIdentifiers } from "./accessControlIdentifiers";
import {
  contentSimilarity,
  isDenied,
  normalise,
  SAME_CONTENT_THRESHOLD,
  DIFFERENT_CONTENT_THRESHOLD,
} from "./accessControlCompare";
import { buildAccessControlFindings } from "./accessControlFindings";

export { namesARecord, mutateIdentifiers, contentSimilarity, isDenied };

// Each candidate costs three requests, so the budget is deliberately small.
const MAX_CANDIDATES = 12;
// Mutation is budgeted separately so it cannot crowd out the direct checks.
const MAX_MUTATIONS = 10;
const TIMEOUT_MS = 8_000;

// ─────────────────────────────────────────────────────────────────────────────
// Probe
// ─────────────────────────────────────────────────────────────────────────────

export interface AccessControlInput {
  /** URLs seen during the authenticated crawl. */
  urls: string[];
  primary: ScanCredentials;
  secondary: ScanCredentials;
  /**
   * True when the scan made the second account itself (autoSecondAccount.ts) rather than being
   * handed one. A signup that drops every new user into one shared workspace makes identical
   * content expected, and an account the user chose as "owns different data" is a statement of
   * fact where an auto-created one is not: the finding says so and is a shade less certain.
   */
  secondaryAutoCreated?: boolean;
}

/**
 * The URLs worth asking two accounts for: the ones that name a record, minus any that would act
 * rather than show. Exported so the scanner can decide, BEFORE creating an account on the
 * customer's system, whether this probe would have anything to use it on.
 */
export function accessControlCandidates(urls: string[]): string[] {
  return [...new Set(urls)]
    .filter((u) => namesARecord(u))
    // Requesting a record as two users is safe; requesting /orders/5/delete as
    // two users deletes it twice.
    .filter((u) => !isDestructiveUrl(u))
    .slice(0, MAX_CANDIDATES);
}

export interface AccessControlOutcome {
  findings: ScanVulnerability[];
  /**
   * How many URLs were actually compared: the first account read real content AND the second
   * account and the anonymous request both got an answer. Zero means the test never compared
   * anything, which is not the same as comparing and finding nothing.
   */
  compared: number;
}

export async function runAccessControlProbes(
  input: AccessControlInput,
): Promise<ScanVulnerability[]> {
  return (await runAccessControlProbesDetailed(input)).findings;
}

export async function runAccessControlProbesDetailed(
  input: AccessControlInput,
): Promise<AccessControlOutcome> {
  const candidates = accessControlCandidates(input.urls);

  if (candidates.length === 0) return { findings: [], compared: 0 };
  let compared = 0;

  const idorHits: string[] = [];
  const anonHits: string[] = [];
  const enumeratedHits: string[] = [];

  // Records reachable by editing the identifier, discovered from the crawled
  // ones. Budgeted separately so mutation cannot crowd out the direct checks.
  const mutated = [...new Set(candidates.flatMap(mutateIdentifiers))]
    .filter((u) => !candidates.includes(u))
    .filter((u) => !isDestructiveUrl(u))
    .slice(0, MAX_MUTATIONS);

  for (const url of [...candidates, ...mutated]) {
    const isMutation = mutated.includes(url);
    const asOwner = await scanFetch(url, { as: input.primary, timeoutMs: TIMEOUT_MS });
    // Nothing to leak unless the owner themselves gets real content.
    if (!asOwner || asOwner.status < 200 || asOwner.status >= 300) continue;
    if (isDenied(asOwner.status, asOwner.body)) continue;
    if (normalise(asOwner.body).length < 80) continue; // too thin to compare meaningfully

    const [asOther, asNobody] = await Promise.all([
      scanFetch(url, { as: input.secondary, timeoutMs: TIMEOUT_MS }),
      scanFetch(url, { as: null, timeoutMs: TIMEOUT_MS }),
    ]);
    if (!asOther || !asNobody) continue;
    compared++;

    const anonSame =
      !isDenied(asNobody.status, asNobody.body) &&
      contentSimilarity(asOwner.body, asNobody.body) >= SAME_CONTENT_THRESHOLD;

    if (anonSame) {
      // Readable without any session at all. Also means the IDOR comparison
      // below would be meaningless — everyone can read it, so "B can read it"
      // says nothing about authorisation between users.
      anonHits.push(url);
      continue;
    }

    const otherSame =
      !isDenied(asOther.status, asOther.body) &&
      contentSimilarity(asOwner.body, asOther.body) >= SAME_CONTENT_THRESHOLD;

    // Guard against a page that is simply identical for everyone for boring
    // reasons: if B's view is *also* near-identical to the anonymous view, the
    // similarity is telling us about a shared shell, not about access.
    const otherDiffersFromAnon =
      contentSimilarity(asOther.body, asNobody.body) < DIFFERENT_CONTENT_THRESHOLD;

    if (otherSame && otherDiffersFromAnon) {
      // Two separate accounts cannot both own one record, so identical content
      // for both means at least one of them is reading data that is not theirs.
      // For a mutated identifier it also proves the records are enumerable —
      // an attacker does not need to be shown a link to reach them.
      (isMutation ? enumeratedHits : idorHits).push(url);
    }
  }

  const findings = buildAccessControlFindings(
    { idorHits, anonHits, enumeratedHits },
    input.secondaryAutoCreated,
  );

  return { findings, compared };
}

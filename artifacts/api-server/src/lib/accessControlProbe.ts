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
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch, type ScanCredentials } from "./http";
import { isDestructiveUrl } from "./destructive";

// Each candidate costs three requests, so the budget is deliberately small.
const MAX_CANDIDATES = 12;
const TIMEOUT_MS = 8_000;

// Two responses count as "the same content" above this token overlap. Not exact
// equality: real pages carry CSRF tokens, timestamps and nonces that differ on
// every render, and demanding byte equality would miss every genuine finding.
const SAME_CONTENT_THRESHOLD = 0.9;

// Below this, two responses are different enough that B plainly saw something
// else — their own record, or a refusal.
const DIFFERENT_CONTENT_THRESHOLD = 0.6;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─────────────────────────────────────────────────────────────────────────────
// Identifier detection
// ─────────────────────────────────────────────────────────────────────────────

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_ID_RE = /^\d{1,19}$/;
// Long opaque strings — Stripe-style ids, nanoids, Mongo ObjectIds.
const OPAQUE_ID_RE = /^[A-Za-z0-9_-]{8,}$/;
const ID_PARAM_RE = /(^|_)(id|uid|user|account|order|invoice|doc|record|item|ref)(_|$)/i;

/**
 * Does this URL name a particular record?
 *
 * Access control only means something for a specific object. /settings is a
 * page; /orders/1042 is someone's order, and asking for it as another user is
 * a question with a meaningful answer.
 */
export function namesARecord(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  const segments = parsed.pathname.split("/").filter(Boolean);
  for (const segment of segments) {
    if (NUMERIC_ID_RE.test(segment)) return true;
    if (UUID_RE.test(segment)) return true;
    // An opaque segment only counts when it sits under a plural collection —
    // /orders/ab12cd34 reads as a record, /about/team-page does not.
    if (OPAQUE_ID_RE.test(segment) && /\d/.test(segment) && segments.length >= 2) return true;
  }

  for (const [key, value] of parsed.searchParams) {
    if (!ID_PARAM_RE.test(key)) continue;
    if (NUMERIC_ID_RE.test(value) || UUID_RE.test(value) || OPAQUE_ID_RE.test(value)) return true;
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Content comparison
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Strip the parts of a page that legitimately change between two renders, so
 * a CSRF token or a rendered timestamp cannot masquerade as "different data".
 */
function normalise(body: string): string {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/\b[0-9a-f]{16,}\b/gi, " ")           // tokens, nonces, hashes
    .replace(/\b\d{4}-\d{2}-\d{2}[T ][\d:.]+/g, " ") // timestamps
    .replace(/<[^>]+>/g, " ")                       // tags
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

/**
 * Token-overlap similarity, 0 to 1.
 *
 * Jaccard over the word set: robust to reordering and to small dynamic
 * fragments, and cheap enough to run on every comparison.
 */
export function contentSimilarity(a: string, b: string): number {
  const setA = new Set(normalise(a).split(" ").filter(Boolean));
  const setB = new Set(normalise(b).split(" ").filter(Boolean));
  if (setA.size === 0 && setB.size === 0) return 1;
  if (setA.size === 0 || setB.size === 0) return 0;

  let shared = 0;
  for (const token of setA) if (setB.has(token)) shared++;
  return shared / (setA.size + setB.size - shared);
}

/** A response that plainly denies access, whatever its status code. */
function isDenied(status: number, body: string): boolean {
  if (status === 401 || status === 403 || status === 404) return true;
  if (status >= 500) return true;
  // Some apps answer 200 with a sign-in page rather than a proper status.
  return (
    /<input[^>]+type=["']password["']/i.test(body.slice(0, 4_000)) ||
    /\b(sign in|log in|login required|unauthorized|access denied|permission denied)\b/i.test(
      body.slice(0, 2_000),
    )
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe
// ─────────────────────────────────────────────────────────────────────────────

export interface AccessControlInput {
  /** URLs seen during the authenticated crawl. */
  urls: string[];
  primary: ScanCredentials;
  secondary: ScanCredentials;
}

export async function runAccessControlProbes(
  input: AccessControlInput,
): Promise<ScanVulnerability[]> {
  const candidates = [...new Set(input.urls)]
    .filter((u) => namesARecord(u))
    // Requesting a record as two users is safe; requesting /orders/5/delete as
    // two users deletes it twice.
    .filter((u) => !isDestructiveUrl(u))
    .slice(0, MAX_CANDIDATES);

  if (candidates.length === 0) return [];

  const idorHits: string[] = [];
  const anonHits: string[] = [];

  for (const url of candidates) {
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

    if (otherSame && otherDiffersFromAnon) idorHits.push(url);
  }

  const findings: ScanVulnerability[] = [];

  if (idorHits.length > 0) {
    findings.push(
      vuln({
        name: "Broken Object-Level Authorisation (IDOR)",
        severity: "critical",
        category: "Broken Access Control",
        description:
          `A second, unrelated account was served the same records as the first at ${idorHits.length} ` +
          `URL${idorHits.length > 1 ? "s" : ""}. The application checks that someone is signed in, but not ` +
          `that they own the record they asked for — so any user can read another user's data by changing ` +
          `the identifier in the URL. This is the most commonly exploited web vulnerability class, and it ` +
          `requires no tooling: a customer can trip over it by editing their address bar.`,
        evidence:
          `Requested as two separate accounts and as an anonymous visitor.\n` +
          `Both accounts received matching content; the anonymous request was refused.\n\n` +
          idorHits.map((u) => `  ${u}`).join("\n"),
        solution:
          "Authorise the object, not just the session. On every request that loads a record by id, confirm " +
          "the record belongs to the caller — a WHERE clause scoped to the current user id, or an explicit " +
          "ownership check before returning it. Do not rely on identifiers being hard to guess; sequential " +
          "ids simply make it faster. Apply the same check to every verb, including update and delete.",
        cweId: "CWE-639",
        cvssScore: 8.1,
        wstgId: "WSTG-ATHZ-04",
        confidence: 90,
      }),
    );
  }

  if (anonHits.length > 0) {
    findings.push(
      vuln({
        name: "Records Readable Without Signing In",
        severity: "high",
        category: "Broken Access Control",
        description:
          `${anonHits.length} URL${anonHits.length > 1 ? "s that name specific records were" : " that names a specific record was"} ` +
          `served in full to a request carrying no session at all, matching what the signed-in account saw. ` +
          `If these records are meant to be private, they are currently public to anyone who knows or guesses the address.`,
        evidence:
          `Identical content returned with and without a session:\n\n` +
          anonHits.map((u) => `  ${u}`).join("\n"),
        solution:
          "Require an authenticated session on any route that returns a specific record, and authorise the " +
          "record against that session. If these particular pages are meant to be public, no change is needed — " +
          "but confirm that deliberately rather than by default.",
        cweId: "CWE-306",
        cvssScore: 7.5,
        wstgId: "WSTG-ATHZ-02",
        confidence: 75,
      }),
    );
  }

  return findings;
}

/**
 * A01 access-control probe: which URLs name a record, and which neighbouring
 * records an attacker would reach by editing the identifier.
 *
 * Split out of accessControlProbe.ts, which keeps the orchestration and
 * re-exports both functions from here, so existing imports are unchanged.
 * Pure string/URL work with no network access: it decides what is worth
 * asking for, never asks.
 */

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
// Identifier mutation
// ─────────────────────────────────────────────────────────────────────────────

/** Neighbours tried for a numeric id. Small, and deliberately not a sweep. */
const NUMERIC_OFFSETS = [1, -1, 2];

/**
 * Records an attacker would find by editing the address bar.
 *
 * Testing only the URLs the crawl reached answers "can another user read what
 * this user was shown". It misses the other half, which is where real breaches
 * come from: records nobody linked to, found by changing 1042 to 1043.
 *
 * UUIDs are deliberately not mutated. Guessing one is infeasible, and that is
 * precisely why they are the recommended fix — enumerating them would burn the
 * request budget to prove nothing.
 */
export function mutateIdentifiers(url: string): string[] {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return [];
  }

  const out = new Set<string>();

  const segments = parsed.pathname.split("/");
  segments.forEach((segment, index) => {
    if (!NUMERIC_ID_RE.test(segment)) return;
    const value = Number(segment);
    // Below 1 stops being an id and starts being a different route.
    for (const offset of NUMERIC_OFFSETS) {
      const next = value + offset;
      if (next < 1 || next === value) continue;
      const copy = [...segments];
      copy[index] = String(next);
      const mutated = new URL(parsed.toString());
      mutated.pathname = copy.join("/");
      out.add(mutated.toString());
    }
  });

  for (const [key, value] of parsed.searchParams) {
    if (!ID_PARAM_RE.test(key) || !NUMERIC_ID_RE.test(value)) continue;
    for (const offset of NUMERIC_OFFSETS) {
      const next = Number(value) + offset;
      if (next < 1) continue;
      const mutated = new URL(parsed.toString());
      mutated.searchParams.set(key, String(next));
      out.add(mutated.toString());
    }
  }

  out.delete(url);
  return [...out];
}

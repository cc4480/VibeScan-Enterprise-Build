/**
 * A01 access-control probe: how two responses are compared.
 *
 * Split out of accessControlProbe.ts, which keeps the orchestration and
 * re-exports contentSimilarity and isDenied from here, so existing imports
 * (autoSecondAccount.ts among them) are unchanged. Pure functions over status
 * codes and bodies, with no network access. normalise and the two thresholds
 * are shared with the probe, which applies them leg by leg.
 */

import type { ScanCredentials } from "./http";

// Two responses count as "the same content" above this token overlap. Not exact
// equality: real pages carry CSRF tokens, timestamps and nonces that differ on
// every render, and demanding byte equality would miss every genuine finding.
export const SAME_CONTENT_THRESHOLD = 0.9;

// Below this, two responses are different enough that B plainly saw something
// else — their own record, or a refusal.
export const DIFFERENT_CONTENT_THRESHOLD = 0.6;

// ─────────────────────────────────────────────────────────────────────────────
// Content comparison
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Strip the parts of a page that legitimately change between two renders, so
 * a CSRF token or a rendered timestamp cannot masquerade as "different data".
 */
export function normalise(body: string): string {
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
export function isDenied(status: number, body: string): boolean {
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
// Shell detection and identity
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A page that is only the app's layout, with the record still to be fetched by script. Two
 * accounts get the same one because the layout is the same, not because they share a record.
 */
export function looksLikeShell(body: string): boolean {
  const text = normalise(body);
  if (/\b(loading|please wait|fetching|skeleton)\b/.test(text)) return true;
  return /aria-busy=["']true|class=["'][^"']*(skeleton|spinner|loading)/i.test(body.slice(0, 20_000));
}

function identityKey(c: ScanCredentials): { cookies: string; headers: string } {
  return {
    cookies: (c.cookie ?? "").split(";").map((x) => x.trim()).filter(Boolean).sort().join(";"),
    headers: Object.entries(c.headers ?? {})
      .map(([k, v]) => `${k.toLowerCase()}:${v.trim()}`)
      .sort()
      .join("\n"),
  };
}

/**
 * True when both sessions would sign in as the same user: identical cookie set and headers, or the
 * same Authorization value. Comparing an account with itself makes every record "shared".
 */
export function sameIdentity(a: ScanCredentials, b: ScanCredentials): boolean {
  const ka = identityKey(a);
  const kb = identityKey(b);
  if (!ka.cookies && !ka.headers && !kb.cookies && !kb.headers) return false; // nothing to compare
  const authA = a.headers && Object.entries(a.headers).find(([k]) => k.toLowerCase() === "authorization")?.[1]?.trim();
  const authB = b.headers && Object.entries(b.headers).find(([k]) => k.toLowerCase() === "authorization")?.[1]?.trim();
  if (authA && authA === authB) return true;
  return ka.cookies === kb.cookies && ka.headers === kb.headers;
}

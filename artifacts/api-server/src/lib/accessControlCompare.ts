/**
 * A01 access-control probe: how two responses are compared.
 *
 * Split out of accessControlProbe.ts, which keeps the orchestration and
 * re-exports contentSimilarity and isDenied from here, so existing imports
 * (autoSecondAccount.ts among them) are unchanged. Pure functions over status
 * codes and bodies, with no network access. normalise and the two thresholds
 * are shared with the probe, which applies them leg by leg.
 */

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

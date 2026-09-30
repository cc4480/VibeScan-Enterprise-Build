/**
 * Values, and variable names, that are public by design. Shared by secret-pattern-data.ts (frontend
 * bundles) and configSecrets.ts (repository config files) so the two cannot disagree about what a
 * Stripe publishable key is.
 *
 * A vendor ships these to the browser on purpose: Stripe pk_live_/pk_test_, Supabase
 * sb_publishable_* and anon-role JWTs, Mapbox pk.ey…, Firebase/Google AIza… web keys, PostHog phc_…,
 * Sentry DSNs. Putting one under a NEXT_PUBLIC_/VITE_/.env name is the vendor's documented setup, not
 * a leak. Only what the key can reach (an open table, an unrestricted quota) is ever a finding.
 */

/** The payload of a JWT-shaped string, or null when it does not parse as base64url JSON. */
export function jwtPayload(token: string): Record<string, unknown> | null {
  const b64 = token.split(".")[1];
  if (!b64) return null;
  try {
    const padded = b64.replace(/-/g, "+").replace(/_/g, "/").padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
    const payload: unknown = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    return typeof payload === "object" && payload !== null ? (payload as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Is this value one a vendor publishes on purpose? Judged by the value alone, except a reCAPTCHA
 * key: site keys and secret keys share the 6L… format, so it counts as public only when the
 * variable's name says "site".
 */
export function isPublicByDesignValue(value: string, name = ""): boolean {
  const v = value.trim();
  if (/^pk_(?:live|test)_[0-9A-Za-z]{16,}$/.test(v)) return true;
  if (/^sb_publishable_[\w-]{16,}$/.test(v)) return true;
  if (/^AIza[0-9A-Za-z_-]{35,}$/.test(v)) return true;
  if (/^pk\.ey[0-9A-Za-z._-]{50,}$/.test(v)) return true;
  if (/^phc_[0-9A-Za-z]{30,}$/.test(v)) return true;
  if (/^https:\/\/[0-9a-f]{16,}(?::[0-9a-f]+)?@[\w.-]*sentry\.io\/\d+$/i.test(v)) return true;
  if (/^6L[0-9A-Za-z_-]{38}$/.test(v) && /site/i.test(name)) return true;
  if (/^eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+$/.test(v)) return jwtPayload(v)?.["role"] === "anon";
  return false;
}

/** Variable names that hold a key the vendor publishes: NEXT_PUBLIC_*_PUBLISHABLE_KEY, ALGOLIA_SEARCH_API_KEY. */
const PUBLIC_KEY_NAME = /publishable|anonkey|anonpublic|searchonly(?:api)?key|searchapikey|searchkey|sitekey|browserkey|publickey/;

export const isPublicByDesignName = (normalisedKey: string): boolean => PUBLIC_KEY_NAME.test(normalisedKey);

/**
 * What a scan skipped because the domain is not verified.
 *
 * Active tests (injection, the API tests, Supabase and Firebase depth, cross-account access
 * control and more) only run against a site whose owner has proven they own it. A scan of an
 * unverified address therefore skips a large share of its tests, and each one says why in the
 * test ledger. This turns those skips into something a person can act on: how many, which, and
 * the page where verifying fixes it.
 *
 * Matched on the ledger's reason text, which the server writes (NOT_VERIFIED in
 * api-server/src/lib/testLedger.ts). A server test pins that the text still starts with this
 * prefix, so rewording it there fails a test instead of silently removing the banner.
 */
export const NOT_VERIFIED_PREFIX = "domain not verified";

interface LedgerTest {
  name: string;
  status: string;
  reason?: string;
}

export interface VerificationGap {
  /** Tests skipped for want of a verified domain. */
  count: number;
  /** Their names, in ledger order, without repeats. */
  names: string[];
  /** All tests in the ledger. */
  total: number;
}

/** The tests the scan skipped because the domain is not verified. Empty when none were. */
export function verificationGap(tests: readonly LedgerTest[] | null | undefined): VerificationGap {
  const list = Array.isArray(tests) ? tests : [];
  const skipped = list.filter(
    (t) => t.status === "skipped" && typeof t.reason === "string" && t.reason.startsWith(NOT_VERIFIED_PREFIX),
  );
  return { count: skipped.length, names: Array.from(new Set(skipped.map((t) => t.name))), total: list.length };
}

/** The scanned site's hostname, or null when the address does not parse. */
export function scannedHost(targetUrl: string | null | undefined): string | null {
  if (!targetUrl) return null;
  try {
    const host = new URL(targetUrl).hostname.toLowerCase();
    return host.length > 0 ? host : null;
  } catch {
    return null;
  }
}

/** The verification page with this site's domain already filled in. */
export function verifyHref(targetUrl: string | null | undefined): string {
  const host = scannedHost(targetUrl);
  return host ? `/domains?domain=${encodeURIComponent(host)}` : "/domains";
}

/** "A, B and 2 more" for the examples in the banner. */
export function exampleList(names: readonly string[], max = 4): string {
  if (names.length === 0) return "";
  if (names.length <= max) {
    if (names.length === 1) return names[0]!;
    return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  }
  return `${names.slice(0, max).join(", ")} and ${names.length - max} more`;
}

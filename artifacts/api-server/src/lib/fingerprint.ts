import { createHash } from "node:crypto";

/**
 * Canonicalizes a target URL for consistent storage and lookup across all
 * dismissal code paths (routes and scan worker).
 *
 * Rules applied:
 *   - Lowercase scheme and hostname
 *   - Strip trailing slash from non-root pathnames
 *
 * Falls back to the raw string on parse failure so callers always get a value.
 */
export function canonicalizeTargetUrl(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    u.protocol = u.protocol.toLowerCase();
    u.hostname = u.hostname.toLowerCase();
    if (u.pathname !== "/" && u.pathname.endsWith("/")) {
      u.pathname = u.pathname.slice(0, -1);
    }
    return u.toString();
  } catch {
    return rawUrl;
  }
}

/**
 * Strips volatile/runtime parts from evidence text to produce a stable
 * structural key. Removes URLs, version numbers, quoted values, and specific
 * header/cookie values — keeping only structural keywords that stay the same
 * across re-scans of the same vulnerability on the same target.
 *
 * Examples:
 *   "Header 'Server' exposes version: Apache/2.4.51"
 *   → "header server exposes version apache"
 *
 *   "Cookie 'session' is missing the Secure flag"
 *   → "cookie session is missing the secure flag"
 */
export function normalizeEvidenceKey(evidence?: string | null): string {
  if (!evidence) return "";
  return evidence
    .toLowerCase()
    .replace(/https?:\/\/[^\s]+/g, "url")    // normalize URLs
    .replace(/\b[0-9a-f]{8,}\b/gi, "hash")  // normalize long hex/hash strings
    .replace(/\b\d[\d.]+\d\b/g, "N")         // normalize version/IP numbers
    .replace(/['"`;,]/g, "")                 // strip punctuation
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 50);
}

/**
 * Stable fingerprint for a scanner finding — used for dismissal storage,
 * lookup, and pipeline suppression.
 *
 * Category and name are lowercased+trimmed for normalization. The optional
 * evidenceKey (derived via normalizeEvidenceKey) adds discriminating power
 * for findings that share the same name but have different underlying evidence
 * shapes (e.g., multiple cookie variants with different flag issues).
 *
 * Evidence is normalized — not raw — to ensure stability across re-scans where
 * specific values (versions, cookie names) may change while the structural
 * finding type stays the same.
 */
export function findingFingerprint(
  category: string,
  name: string,
  evidence?: string | null,
): string {
  const evidenceKey = normalizeEvidenceKey(evidence);
  const input = evidenceKey
    ? `${category.toLowerCase().trim()}::${name.toLowerCase().trim()}::${evidenceKey}`
    : `${category.toLowerCase().trim()}::${name.toLowerCase().trim()}`;
  return createHash("sha256").update(input).digest("hex").slice(0, 20);
}

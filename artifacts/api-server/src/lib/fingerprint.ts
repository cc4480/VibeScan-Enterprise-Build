import { createHash } from "node:crypto";

/**
 * Stable fingerprint for a scanner finding — used for dismissal storage,
 * lookup, and pipeline suppression. Both inputs are lowercased and trimmed
 * before hashing so the same underlying issue always produces the same key
 * regardless of minor name/category formatting variations.
 */
export function findingFingerprint(category: string, name: string): string {
  return createHash("sha256")
    .update(`${category.toLowerCase().trim()}::${name.toLowerCase().trim()}`)
    .digest("hex")
    .slice(0, 20);
}

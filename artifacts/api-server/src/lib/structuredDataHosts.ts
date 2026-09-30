/**
 * Finds internal hosts in JSON-LD, judging only URL-valued fields and only the
 * host of a parsed URL.
 *
 * Matching hostname-shaped text anywhere in any string flagged articles that
 * merely discuss "localhost:3000", a "10.15.7.1" macOS version, or files named
 * "foo.test" or "settings.local". Those describe things; a URL field points at one.
 */

/** JSON-LD properties whose value is a URL (schema.org "URL"-typed, plus @id and image-like fields). */
const URL_KEYS = new Set([
  "url", "@id", "sameas", "image", "logo", "contenturl", "thumbnailurl", "embedurl", "mainentityofpage",
  "item", "target", "urltemplate", "downloadurl", "installurl", "coderepository",
  "discussionurl", "relatedlink", "significantlink", "hasmap", "map", "isbasedon", "license", "video", "audio",
]);

const INTERNAL_SUFFIXES = [".local", ".internal", ".lan", ".intranet", ".corp", ".test", ".localdomain", ".localhost"];

function isInternalHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || h === "[::1]") return true;
  if (INTERNAL_SUFFIXES.some((s) => h.endsWith(s))) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}

/** The string is an absolute http(s) URL (or protocol-relative) whose host is internal. */
export function urlHasInternalHost(value: string): boolean {
  const s = value.trim();
  if (!/^(https?:)?\/\//i.test(s)) return false;
  try {
    return isInternalHost(new URL(s.startsWith("//") ? `https:${s}` : s).hostname);
  } catch {
    return false;
  }
}

/** Every URL-field string in the document whose host is internal (first occurrences, bounded). */
export function internalUrlsIn(value: unknown, out = new Set<string>(), viaUrlKey = false, depth = 0): Set<string> {
  if (depth > 12 || out.size > 50) return out;
  if (typeof value === "string") {
    if (viaUrlKey && urlHasInternalHost(value)) out.add(value.trim().slice(0, 160));
  } else if (Array.isArray(value)) {
    for (const v of value) internalUrlsIn(v, out, viaUrlKey, depth + 1);
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      internalUrlsIn(v, out, URL_KEYS.has(k.toLowerCase()), depth + 1);
    }
  }
  return out;
}

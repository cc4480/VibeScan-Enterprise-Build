/** Reading page metadata and JSON-LD out of the fetched HTML. */
/** Cap on how much of a document is scanned for tags. */
export const MAX_HTML_BYTES = 512_000;

/** Cap on a single JSON-LD block, so a pathological document cannot stall a scan. */
export const MAX_JSONLD_BYTES = 200_000;

export interface JsonLdBlock {
  raw: string;
  /** Parsed value, or null when the block is not valid JSON. */
  value: unknown;
  parseError: string | null;
}

export interface PageMetadata {
  /** Lowercased meta name/property → content, first occurrence wins. */
  meta: Map<string, string>;
  canonical: string | null;
  jsonLd: JsonLdBlock[];
  title: string | null;
}

// ── extraction ─────────────────────────────────────────────────────────────

export function decodeEntities(s: string): string {
  return s
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&");
}

/**
 * Pull the content of a tag attribute.
 *
 * Handles single, double and unquoted values because real documents use all
 * three, and a check that only reads double-quoted attributes silently sees
 * nothing on the sites that need it most.
 */
export function attr(tag: string, name: string): string | null {
  const re = new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s"'>]+))`, "i");
  const m = re.exec(tag);
  if (!m) return null;
  return decodeEntities(m[2] ?? m[3] ?? m[4] ?? "").trim();
}

export function extractPageMetadata(html: string): PageMetadata {
  const doc = html.slice(0, MAX_HTML_BYTES);
  const meta = new Map<string, string>();

  for (const m of doc.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    // property= is the Open Graph spelling, name= the HTML one. Twitter Cards
    // appear under both in the wild, so neither can be assumed.
    const key = (attr(tag, "property") ?? attr(tag, "name"))?.toLowerCase();
    const content = attr(tag, "content");
    if (!key || content === null) continue;
    if (!meta.has(key)) meta.set(key, content);
  }

  let canonical: string | null = null;
  for (const m of doc.matchAll(/<link\b[^>]*>/gi)) {
    const rel = attr(m[0], "rel")?.toLowerCase();
    if (rel === "canonical") {
      canonical = attr(m[0], "href");
      break;
    }
  }

  const jsonLd: JsonLdBlock[] = [];
  for (const m of doc.matchAll(
    /<script\b[^>]*\btype\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script\s*>/gi,
  )) {
    const raw = (m[1] ?? "").trim();
    if (!raw) {
      jsonLd.push({ raw, value: null, parseError: "empty block" });
      continue;
    }
    if (raw.length > MAX_JSONLD_BYTES) {
      // Too large to parse safely; record it without claiming it is malformed.
      jsonLd.push({ raw: raw.slice(0, 200), value: null, parseError: null });
      continue;
    }
    try {
      jsonLd.push({ raw, value: JSON.parse(raw), parseError: null });
    } catch (err) {
      jsonLd.push({ raw, value: null, parseError: (err as Error).message.slice(0, 120) });
    }
  }

  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(doc);
  const title = titleMatch ? decodeEntities(titleMatch[1] ?? "").trim() : null;

  return { meta, canonical, jsonLd, title };
}

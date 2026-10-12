/**
 * Source map exposure check.
 *
 * Bundlers (webpack, Vite, esbuild, Parcel) optionally emit .map files that
 * contain the full un-minified source — identical to shipping your source code.
 * These are frequently deployed to production by accident.
 *
 * Approach:
 *  1. Extract all <script src="…"> URLs from the page HTML.
 *  2. For each external JS file (up to 8), request <url>.map directly.
 *  3. Also scan the last 512 bytes of each JS file for a
 *     "//# sourceMappingURL=…" comment pointing to a named map file.
 *  4. Confirm a finding only when the response is valid source-map JSON
 *     (has "sources" array with ≥1 entry, or "sourcesContent" present).
 *
 * Runs on both tiers (only HEAD + small trailer fetches — fast).
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";

const TIMEOUT_MS = 8_000;
const MAX_JS_FILES = 8;
const MAX_MAP_BYTES = 40 * 1024 * 1024;
const MAP_TIMEOUT_MS = 20_000;
const TRAILER_BYTES = 512;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function tryFetch(
  url: string,
  rangeHeader?: string,
): Promise<{ ok: boolean; body: string; ct: string } | null> {
  const headers: Record<string, string> = {};
  if (rangeHeader) headers["Range"] = rangeHeader;

  // A whole map has to be read to be judged (which sources are the site's own, whether source text is embedded), and a map with
  // embedded source passes the default 5 MiB body limit in an ordinary app. The trailer read of a script is a Range request
  // and stays small.
  const res = await scanFetch(url, { headers, timeoutMs: rangeHeader ? TIMEOUT_MS : MAP_TIMEOUT_MS, ...(rangeHeader ? {} : { maxBodyBytes: MAX_MAP_BYTES }) });
  // 206 is expected when a Range header was sent, so it counts alongside 2xx.
  if (!res || (res.status < 200 || res.status >= 300) && res.status !== 206) return null;
  return { ok: true, body: res.body, ct: res.headers["content-type"] ?? "" };
}

function extractJsUrls(html: string, baseUrl: string): string[] {
  const srcRx = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  const urls: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = srcRx.exec(html)) !== null) {
    try {
      const abs = new URL(m[1]!, baseUrl).href;
      // Only external bundled scripts (skip CDN libs — they publish maps intentionally)
      const host = new URL(baseUrl).hostname;
      if (new URL(abs).hostname === host) urls.push(abs);
    } catch { /* skip */ }
  }
  return [...new Set(urls)].slice(0, MAX_JS_FILES);
}

function isValidSourceMap(body: string): boolean {
  try {
    const json = JSON.parse(body) as Record<string, unknown>;
    const sources = json["sources"];
    return (
      Array.isArray(sources) &&
      sources.length > 0 &&
      (typeof sources[0] === "string")
    );
  } catch {
    return false;
  }
}

function sourceCount(body: string): number {
  try {
    const json = JSON.parse(body) as Record<string, unknown>;
    const sources = json["sources"];
    return Array.isArray(sources) ? sources.length : 0;
  } catch {
    return 0;
  }
}

/** True only when the map actually embeds source text, not just the key (or null placeholders). */
function hasSourceContent(body: string): boolean {
  try {
    const content = (JSON.parse(body) as Record<string, unknown>)["sourcesContent"];
    return Array.isArray(content) && content.some((c) => typeof c === "string" && c.trim().length > 0);
  } catch {
    return false;
  }
}

/**
 * Which of a map's sources are the site's own code, as opposed to bundled libraries.
 *
 * A map is only as sensitive as what it embeds. fastly.com's holds 126 files of which 125 are
 * node_modules packages and one is a Sentry config; archive.org's is a vendored copy of the public
 * lit polyfill. Calling either "Full Source Code Accessible" (High) tells the owner their
 * application is downloadable when nothing of theirs is in it.
 *
 * Own code = a source with embedded text that is not under node_modules, in a map that is not itself
 * served from a vendor directory.
 */
export function ownSources(mapUrl: string, body: string): { total: number; own: string[] } {
  try {
    const json = JSON.parse(body) as Record<string, unknown>;
    const sources = Array.isArray(json["sources"]) ? (json["sources"] as unknown[]).map(String) : [];
    const content = Array.isArray(json["sourcesContent"]) ? (json["sourcesContent"] as unknown[]) : [];
    let path = mapUrl;
    try { path = new URL(mapUrl).pathname; } catch { /* keep as given */ }
    const vendored = /\/(?:vendor|vendors|node_modules|third[-_]?party)\//i.test(path);
    const own = vendored
      ? []
      : sources.filter((s, i) => !/(?:^|[\\/])node_modules[\\/]/.test(s) && typeof content[i] === "string" && (content[i] as string).trim().length > 0);
    return { total: sources.length, own };
  } catch {
    return { total: 0, own: [] };
  }
}

/** Almost nothing in the map is the site's own: fewer than three files and under 5% of the sources. */
export function mostlyLibraryCode(total: number, ownCount: number): boolean {
  return ownCount === 0 || (ownCount < 3 && ownCount / Math.max(total, 1) < 0.05);
}

/**
 * With sourcesContent the original code is downloadable (High); with only a
 * sources list an attacker learns file names and layout but not the code (Low),
 * so the title and severity say which was observed.
 */
function mapFinding(opts: { mapUrl: string; body: string; linkedFrom?: string }): ScanVulnerability {
  const { mapUrl, body, linkedFrom } = opts;
  const n = sourceCount(body);
  const hasContent = hasSourceContent(body);
  const path = (u: string) => { try { return new URL(u).pathname; } catch { return u; } };
  const how = linkedFrom ? "is linked from the production bundle and " : "";
  if (hasContent) {
    const { total, own } = ownSources(mapUrl, body);
    if (mostlyLibraryCode(total, own.length)) {
      const ownNote = own.length === 0 ? "none of it is this site's own code" : `only ${own.length} of its ${total} files are this site's own`;
      return vuln({
        name: "JavaScript Source Map Exposed — Third-Party Library Code",
        severity: "low",
        category: "Source Code Exposure",
        description: `A JavaScript source map ${how}is publicly accessible at ${path(mapUrl)} and embeds source text, but ${ownNote}: the rest is third-party library code that is already public. Anyone can read what the bundle is made of, and the library versions, but not the application's logic.`,
        evidence: `${linkedFrom ? `Linked from: ${path(linkedFrom)}\n` : ""}Source map URL: ${mapUrl}\nSource files mapped: ${total}, of which the site's own: ${own.length}${own.length ? `\n${own.slice(0, 5).map((s) => `  • ${s}`).join("\n")}` : ""}`,
        solution: "Disable source map generation in production builds, or serve maps only to your error-reporting service (Webpack: devtool: 'hidden-source-map'). If the map belongs to a vendored library, no action is needed.",
        cweId: "CWE-540",
        cvssScore: 3.1,
        wstgId: "WSTG-CONF-04",
        confidence: 80,
      });
    }
  }
  return vuln({
    name: hasContent
      ? "JavaScript Source Map Exposed — Full Source Code Accessible"
      : "JavaScript Source Map Exposed — Source File Names Only",
    severity: hasContent ? "high" : "low",
    category: "Source Code Exposure",
    description: hasContent
      ? `A JavaScript source map ${how}is publicly accessible at ${path(mapUrl)}. It embeds the original source text (sourcesContent), so anyone can reconstruct the application's source: comments, variable names, file paths, internal endpoints and any secrets present at build time.`
      : `A JavaScript source map ${how}is publicly accessible at ${path(mapUrl)}. It lists ${n} source file names but does not embed their contents, so it discloses project structure and dependency paths rather than the code itself.`,
    evidence: `${linkedFrom ? `Linked from: ${path(linkedFrom)}\n` : ""}Source map URL: ${mapUrl}\nSource files mapped: ${n}${hasContent ? "\nFull sourcesContent included." : "\nNo sourcesContent (file names only)."}`,
    solution: "Disable source map generation in production builds. Webpack: set devtool: false or devtool: 'hidden-source-map' (generates maps but does not link them from the bundle). Vite: set build.sourcemap: false. If you need source maps for error tracking, upload them directly to your error tracker (Sentry, Datadog) and keep them off the public server.",
    cweId: "CWE-540",
    cvssScore: hasContent ? 7.5 : 3.7,
    wstgId: "WSTG-CONF-04",
  });
}

// ─── Main export ──────────────────────────────────────────────────────────────

export async function checkSourceMaps(
  html: string,
  baseUrl: string,
  /** Told why, when there was nothing here to test (recorded as "not tested", not "ran"). */
  notTested?: (reason: string) => void,
): Promise<ScanVulnerability[]> {
  const jsUrls = extractJsUrls(html, baseUrl);
  if (jsUrls.length === 0) {
    notTested?.("the page loads no JavaScript files of its own to look for source maps beside");
    return [];
  }

  const results = await Promise.allSettled(
    jsUrls.map(async (jsUrl): Promise<ScanVulnerability | null> => {
      // 1. Try the obvious <url>.map directly
      const directMapUrl = jsUrl + ".map";
      const direct = await tryFetch(directMapUrl);
      if (direct && isValidSourceMap(direct.body)) {
        return mapFinding({ mapUrl: directMapUrl, body: direct.body });
      }

      // 2. Fetch the last TRAILER_BYTES of the JS file to find sourceMappingURL comment
      const trailer = await tryFetch(jsUrl, `bytes=-${TRAILER_BYTES}`);
      if (!trailer) return null;

      const mappingMatch = /\/\/# sourceMappingURL=([^\s]+)/.exec(trailer.body);
      if (!mappingMatch) return null;

      const rawMapping = mappingMatch[1]!;
      // Skip data: URIs (inline maps — not a server exposure)
      if (rawMapping.startsWith("data:")) return null;

      let mapUrl: string;
      try {
        mapUrl = new URL(rawMapping, jsUrl).href;
        // Only check same-origin maps
        if (new URL(mapUrl).hostname !== new URL(baseUrl).hostname) return null;
      } catch {
        return null;
      }

      const linked = await tryFetch(mapUrl);
      if (!linked || !isValidSourceMap(linked.body)) return null;

      return mapFinding({ mapUrl, body: linked.body, linkedFrom: jsUrl });
    }),
  );

  // Deduplicate — only report once even if multiple JS files have exposed maps
  const seen = new Set<string>();
  return results
    .filter((r): r is PromiseFulfilledResult<ScanVulnerability | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((v): v is ScanVulnerability => {
      if (!v) return false;
      if (seen.has(v.name)) return false;
      seen.add(v.name);
      return true;
    });
}

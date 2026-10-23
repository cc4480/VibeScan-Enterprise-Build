/**
 * Pure decision logic for the passive response-header and page checks that
 * scanner.ts turns into findings: CSP weakness, X-Content-Type-Options, and
 * mixed content.
 *
 * Kept out of scanner.ts so each rule can be tested against the benign policies
 * and pages that used to trip it, without running a whole scan.
 */

/** Directive name (lowercase) to its space-separated source tokens (case preserved). */
export function parseCsp(csp: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const seg of csp.split(";").map((s) => s.trim()).filter(Boolean)) {
    const [name, ...tokens] = seg.split(/\s+/);
    // The first occurrence of a directive wins; later duplicates are ignored by browsers.
    if (!map.has(name.toLowerCase())) map.set(name.toLowerCase(), tokens);
  }
  return map;
}

const has = (tokens: string[], kw: string) => tokens.some((t) => t.toLowerCase() === `'${kw}'`);

/**
 * CSP2+ browsers ignore 'unsafe-inline' whenever a nonce, a hash or
 * 'strict-dynamic' is present in the same source list — it is only a fallback
 * for browsers that do not understand them. So it is not an effective weakness
 * in that case.
 */
function inlineIsNeutralised(tokens: string[]): boolean {
  return tokens.some((t) => /^'(nonce-|sha(256|384|512)-)/i.test(t)) || has(tokens, "strict-dynamic");
}

export interface CspVerdict {
  /** 'unsafe-inline' is effective for scripts (no nonce/hash/strict-dynamic beside it). */
  scriptUnsafeInline: boolean;
  /** 'unsafe-eval' allows eval(). 'wasm-unsafe-eval' is a different, narrower keyword and is not counted. */
  scriptUnsafeEval: boolean;
  /** 'unsafe-inline' is effective for styles. */
  styleUnsafeInline: boolean;
  /** The policy tells browsers to upgrade http:// subresource requests to https://. */
  upgradeInsecureRequests: boolean;
}

/** script-src and style-src fall back to default-src when absent. */
export function analyzeCsp(csp: string): CspVerdict {
  const dirs = parseCsp(csp);
  const fallback = dirs.get("default-src") ?? [];
  const script = dirs.get("script-src") ?? fallback;
  const style = dirs.get("style-src") ?? fallback;
  return {
    scriptUnsafeInline: has(script, "unsafe-inline") && !inlineIsNeutralised(script),
    scriptUnsafeEval: has(script, "unsafe-eval"),
    styleUnsafeInline: has(style, "unsafe-inline") && !inlineIsNeutralised(style),
    upgradeInsecureRequests: dirs.has("upgrade-insecure-requests"),
  };
}

const META_ENTITIES: Record<string, string> = { "&amp;": "&", "&quot;": '"', "&#39;": "'", "&apos;": "'", "&lt;": "<", "&gt;": ">" };

/**
 * The policy a page delivers through <meta http-equiv="Content-Security-Policy" content="...">, or null.
 *
 * Browsers enforce it (frame-ancestors, report-uri and sandbox excepted), so a page with no CSP header
 * but this tag has a CSP: calling it "missing" is wrong, and its directives deserve the same analysis
 * as a header's. gitlab.com's marketing site is delivered this way. A Report-Only meta is not honoured
 * by browsers and is ignored here.
 */
export function extractMetaCsp(html: string): string | null {
  // A commented-out tag is not a policy.
  const live = html.slice(0, 300_000).replace(/<!--[\s\S]*?-->/g, "");
  for (const m of live.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    const equiv = /http-equiv\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    if ((equiv?.[1] ?? equiv?.[2] ?? equiv?.[3] ?? "").trim().toLowerCase() !== "content-security-policy") continue;
    const content = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tag);
    const value = (content?.[1] ?? content?.[2] ?? "").replace(/&(?:amp|quot|#39|apos|lt|gt);/g, (e) => META_ENTITIES[e] ?? e).replace(/\s+/g, " ").trim();
    if (value) return value;
  }
  return null;
}

/**
 * A CDN in front of an origin that both set the header yields
 * "nosniff, nosniff"; browsers accept it, so any list member equal to nosniff counts.
 */
export function hasNosniff(value: string | undefined): boolean {
  return !!value && value.split(",").some((v) => v.trim().toLowerCase() === "nosniff");
}

/**
 * Whether a Content-Security-Policy header limits who may frame the page. Naming the directive is not
 * enough: `frame-ancestors *` (or a bare `https:` scheme) lets every origin embed the page. Policies
 * joined by fetch with a comma are enforced together, so one restrictive policy is enough.
 */
export function cspRestrictsFraming(csp: string | undefined): boolean {
  if (!csp) return false;
  return csp.split(",").some((policy) => {
    const directive = policy.split(";").map((d) => d.trim().split(/\s+/)).find((t) => t[0]?.toLowerCase() === "frame-ancestors");
    if (!directive) return false;
    const sources = directive.slice(1).map((s) => s.toLowerCase());
    return !sources.some((s) => s === "*" || s === "http:" || s === "https:");
  });
}

export interface MixedContentRef {
  tag: string;
  url: string;
  /** Scripts, stylesheets and frames can run or restyle the page; images/media are "passive". */
  active: boolean;
}

const ATTR_RE = /([^\s=/"'<>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
const LOADING_TAGS = new Set(["script", "img", "link", "iframe", "audio", "video", "source", "embed"]);
const PASSIVE_TAGS = new Set(["img", "audio", "video", "source"]);
const LOADING_LINK_RELS = /\b(stylesheet|icon|apple-touch-icon|preload|modulepreload|prefetch|manifest)\b/i;

/**
 * http:// URLs the browser would actually request as subresources of this page:
 * the src of script/img/iframe/audio/video/source/embed and the href of loading
 * <link> elements. Ignores data-* attributes, <a href>, comments, and text or
 * strings inside inline scripts, none of which load anything.
 */
export function findMixedContent(html: string): MixedContentRef[] {
  const cleaned = html
    .replace(/<!--[\s\S]*?-->/g, "")
    // Keep the opening tag (it may carry src) but drop the inline body.
    .replace(/(<script\b[^>]*>)[\s\S]*?<\/script\s*>/gi, "$1")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, "");
  const found: MixedContentRef[] = [];
  for (const m of cleaned.matchAll(/<([a-z][a-z0-9-]*)\b([^>]*)>/gi)) {
    const tag = m[1].toLowerCase();
    if (!LOADING_TAGS.has(tag)) continue;
    const attrs = new Map<string, string>();
    for (const a of m[2].matchAll(ATTR_RE)) {
      const key = a[1].toLowerCase();
      if (!attrs.has(key)) attrs.set(key, (a[2] ?? a[3] ?? a[4] ?? "").trim());
    }
    const attr = tag === "link" ? "href" : "src";
    const url = attrs.get(attr);
    if (!url || !/^http:\/\//i.test(url)) continue;
    if (tag === "link" && !LOADING_LINK_RELS.test(attrs.get("rel") ?? "")) continue;
    // Loopback is a potentially-trustworthy origin, so browsers do not treat it as mixed.
    if (/^http:\/\/(localhost|127\.\d+\.\d+\.\d+|\[::1\])([:/]|$)/i.test(url)) continue;
    found.push({ tag, url, active: !PASSIVE_TAGS.has(tag) });
  }
  return found;
}

/**
 * Structural evidence extraction for technology fingerprinting.
 *
 * Technology names feed CVE matching, so a phantom tag becomes a phantom
 * advisory. Matching a vendor's domain or a framework's name anywhere in the
 * HTML tagged every blog post, footer link and SEO keywords meta that merely
 * *mentioned* the product. These helpers separate the three places a site's own
 * technology actually shows up from everything else on the page:
 *
 *  - asset URLs: `<script src>`, `<link href>`, `<img src>` — what the page loads,
 *    never plain `<a href>` links or prose;
 *  - script content: inline `<script>` bodies (executable JS), never visible text;
 *  - `<meta name="generator">` values — never `content=` of an arbitrary meta tag.
 */

/** URLs the page itself loads (not navigates to). */
export function assetUrls(html: string): string[] {
  const urls: string[] = [];
  const tag = /<(script|link|img|source)\b[^>]*>/gi;
  for (const m of html.matchAll(tag)) {
    const attr = m[1].toLowerCase() === "link" ? "href" : "src";
    const v = new RegExp(`\\s${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(m[0]);
    const url = v?.[1] ?? v?.[2] ?? v?.[3];
    if (url) urls.push(url);
  }
  return urls;
}

/** Concatenated bodies of executable inline scripts (JSON-LD/templates excluded). */
export function scriptText(html: string): string {
  const parts: string[] = [];
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const type = /\btype\s*=\s*["']?([^"'\s>]+)/i.exec(m[1])?.[1]?.toLowerCase();
    if (type && !/javascript|module|ecmascript/.test(type)) continue;
    parts.push(m[2]);
  }
  return parts.join("\n");
}

/** `content` values of `<meta name="generator">` tags, whichever attribute order. */
export function generators(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    if (!/\bname\s*=\s*["']generator["']/i.test(m[0])) continue;
    const c = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(m[0]);
    if (c) out.push(c[1] ?? c[2] ?? "");
  }
  return out;
}

/** Hostname of an absolute or protocol-relative URL, lowercased; "" if relative. */
export function urlHost(url: string): string {
  const m = /^(?:https?:)?\/\/([^/:?#\s]+)/i.exec(url.trim());
  return m ? m[1].toLowerCase() : "";
}

/** True when any asset URL is served from `domain` or one of its subdomains. */
export function loadsFromHost(urls: string[], ...domains: string[]): boolean {
  return urls.some((u) => {
    const h = urlHost(u);
    return h !== "" && domains.some((d) => h === d || h.endsWith(`.${d}`));
  });
}

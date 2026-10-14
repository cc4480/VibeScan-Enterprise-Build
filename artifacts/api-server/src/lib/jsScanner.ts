/**
 * JavaScript secret scanner — detects hardcoded credentials and sensitive data
 * in inline scripts and external JavaScript files linked from the target page.
 *
 * Patterns cover: AWS, Google, Stripe, GitHub, Slack, Twilio, SendGrid,
 * Mailchimp, private keys, JWTs, Firebase, and generic credential patterns.
 *
 * Only runs on "deep" tier scans to avoid excessive external HTTP requests.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const JS_FETCH_TIMEOUT_MS = 10_000;
const MAX_EXTERNAL_SCRIPTS = 12;
/**
 * Most of a script that is read, per file. This was 512,000, and a production bundle of an ordinary app is
 * larger: in a Vite build the libraries come first and the app's own code, the part that holds its keys, comes
 * last, so a cap that cuts the end cuts off exactly that part (a 761,001-byte bundle lost everything after
 * byte 512,000: the service_role key at 756,7xx and an OpenAI key were never looked at). The transport already
 * stops a body at MAX_BODY_BYTES, so this matches it. Reading it all costs about 50 ms a megabyte on a real
 * bundle, and the patterns that did not scale (see secret-pattern-jwt.ts) are fixed.
 */
const MAX_SCRIPT_SIZE_BYTES = MAX_BODY_BYTES;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─────────────────────────────────────────────────────────────────────────────
// SECRET PATTERNS
// ─────────────────────────────────────────────────────────────────────────────

import type { SecretPattern } from "./secret-pattern-data";
import { scanFetch, oncePerScan } from "./http";
import { MAX_BODY_BYTES } from "./httpBody";
import { scanAiUsage } from "./aiFeatureProbe";
import { isFirstParty } from "./sriPolicy";

// ─────────────────────────────────────────────────────────────────────────────
// EXTRACT SCRIPT CONTENT
// ─────────────────────────────────────────────────────────────────────────────

/** One download per script per scan, shared by every check that reads it. */
function fetchScript(url: string): Promise<string> {
  return oncePerScan(`script:${url}`, () => downloadScript(url));
}

async function downloadScript(url: string): Promise<string> {
  const res = await scanFetch(url, {
    headers: { Expires: "0" },
    timeoutMs: JS_FETCH_TIMEOUT_MS,
  });
  if (!res || res.status < 200 || res.status >= 300) return "";

  const ct = res.headers["content-type"] ?? "";
  if (!ct.includes("javascript") && !ct.includes("text/plain") && !ct.includes("application/")) return "";

  return res.body.slice(0, MAX_SCRIPT_SIZE_BYTES);
}

function extractInlineScripts(html: string): string {
  const inlineRegex = /<script(?:[^>]*)>([\s\S]*?)<\/script>/gi;
  const parts: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = inlineRegex.exec(html)) !== null) {
    const tag = m[0];
    // Skip external scripts (they have a src attribute)
    if (!/\bsrc\s*=/i.test(tag)) {
      parts.push(m[1] ?? "");
    }
  }
  return parts.join("\n");
}

function extractExternalScriptUrls(html: string, baseUrl: string): string[] {
  const srcRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  const urls: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = srcRegex.exec(html)) !== null) {
    try {
      const absolute = new URL(m[1], baseUrl).href;
      urls.push(absolute);
    } catch { /* invalid URL */ }
  }
  // Scripts the page only PRELOADS. TanStack Start and other code-splitting builds put one script tag in the HTML (the
  // entry) and list the other chunks as <link rel="modulepreload">; the project URL, keys and table names sit in
  // those chunks, so a scanner that reads script tags alone never sees them. Script tags first, then the preloads.
  for (const tag of html.match(/<link\b[^>]*>/gi) ?? []) {
    if (!/\brel\s*=\s*["']?modulepreload\b/i.test(tag)) continue;
    const href = /\bhref\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1];
    if (!href) continue;
    try { urls.push(new URL(href, baseUrl).href); } catch { /* invalid URL */ }
  }
  return [...new Set(urls)].slice(0, MAX_EXTERNAL_SCRIPTS);
}

/** Most extra chunks read per scan, on top of the scripts the page itself lists. */
export const MAX_LAZY_CHUNKS = 12;

/**
 * Module chunks the given scripts load on demand: `import("./Admin-3fa9.js")` and the file list a Vite build writes into
 * its preload helper (`__vite__mapDeps`). A route that is code-split (React.lazy) lives in a chunk the HTML never names,
 * and what a lazy admin screen contains (a service_role key, an AI key) is exactly what the entry script does not. Only
 * chunks on the host of the script that loads them, only .js/.mjs, none already read. webpack's chunk maps are not read.
 */
export function lazyChunkUrls(scripts: Array<{ url: string; text: string }>, pageUrl: string, known: Iterable<string>): string[] {
  const seen = new Set(known);
  const out: string[] = [];
  const add = (spec: string, from: string) => {
    if (out.length >= MAX_LAZY_CHUNKS || !/\.m?js(?:\?[^"'`\s]*)?$/i.test(spec)) return;
    try {
      const abs = new URL(spec, from).href;
      if (new URL(abs).hostname !== new URL(from).hostname || seen.has(abs)) return;
      seen.add(abs);
      out.push(abs);
    } catch { /* not a URL */ }
  };
  for (const { url, text } of scripts) {
    for (const m of text.matchAll(/\bimport\(\s*["'`]([^"'`\s]+)["'`]\s*\)/g)) add(m[1]!, url);
    // Vite writes the chunks a dynamic import needs as site-relative paths: m.f||(m.f=["assets/Admin-3fa9.js","assets/x.css"])
    const list = /\.f\s*\|\|\s*\(\s*[\w$.]+\.f\s*=\s*(\[[^\]]*\])/.exec(text)?.[1];
    if (list) {
      try { for (const p of JSON.parse(list) as unknown[]) if (typeof p === "string") add(p.startsWith("/") ? p : new URL(p, new URL("/", pageUrl)).pathname, new URL("/", pageUrl).href); } catch { /* not JSON */ }
    }
  }
  return out;
}

/** The scripts at `urls`, then the lazy chunks they load (see lazyChunkUrls), as url and text pairs. `keep` filters the chunks. */
async function fetchWithLazyChunks(urls: string[], pageUrl: string, keep: (chunkUrl: string) => boolean = () => true): Promise<Array<{ url: string; text: string }>> {
  const first = await Promise.allSettled(urls.map((url) => fetchScript(url)));
  const read = urls.map((url, i) => ({ url, text: first[i]!.status === "fulfilled" ? first[i]!.value : "" }));
  const lazy = lazyChunkUrls(read, pageUrl, urls).filter(keep);
  if (lazy.length === 0) return read;
  const more = await Promise.allSettled(lazy.map((url) => fetchScript(url)));
  return [...read, ...lazy.map((url, i) => ({ url, text: more[i]!.status === "fulfilled" ? more[i]!.value : "" }))];
}

// The secret scan and its redaction live in jsScannerSecrets.ts; re-exported so every import path is unchanged.
export { redactSecret, redactContext, scanContent } from "./jsScannerSecrets";
import { redactSecret, redactContext, scanContent } from "./jsScannerSecrets";

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch the page's inline and external JavaScript, concatenated.
 *
 * Exported so API discovery can read the same bundles this module already
 * downloads, instead of fetching every script a second time.
 */
export async function collectJavaScript(html: string, baseUrl: string): Promise<string> {
  const inline = extractInlineScripts(html);
  const external = await fetchWithLazyChunks(extractExternalScriptUrls(html, baseUrl), baseUrl);
  return [inline, ...external.map((s) => s.text)].join("\n");
}

/**
 * The site's OWN JavaScript: inline scripts plus external ones on the same registrable domain
 * (or the operator's own CDN). Third-party scripts are left out, exactly as the passive AI check
 * leaves them out, because what they contain is a vendor's, not this site's: a chat widget that
 * ships its own system prompt is not evidence about the site's prompt.
 */
export async function collectFirstPartyJavaScript(html: string, baseUrl: string): Promise<string> {
  const urls = extractExternalScriptUrls(html, baseUrl);
  const ownHost = (() => { try { return new URL(baseUrl).hostname; } catch { return ""; } })();
  const hostOf = (url: string) => { try { return new URL(url).hostname; } catch { return ""; } };
  const own = await fetchWithLazyChunks(urls.filter((url) => isFirstParty(ownHost, hostOf(url))), baseUrl, (chunk) => isFirstParty(ownHost, hostOf(chunk)));
  return [extractInlineScripts(html), ...own.map((s) => s.text)].join("\n");
}

export async function scanJavaScriptForSecrets(
  html: string,
  baseUrl: string,
): Promise<ScanVulnerability[]> {
  // 1. Scan inline scripts immediately
  const inlineContent = extractInlineScripts(html);
  const inlineFindings = scanContent(inlineContent);

  // 2. Fetch and scan external scripts in parallel
  const listed = await fetchWithLazyChunks(extractExternalScriptUrls(html, baseUrl), baseUrl);
  const externalUrls = listed.map((s) => s.url);
  const externalContents = listed.map((s) => ({ status: "fulfilled" as const, value: s.text }));

  const allExternalFindings: Array<{ pattern: SecretPattern; match: string; context: string; url: string }> = [];
  const pageHost = (() => { try { return new URL(baseUrl).hostname; } catch { return ""; } })();
  externalContents.forEach((result, i) => {
    if (result.status === "fulfilled" && result.value) {
      const scriptHost = (() => { try { return new URL(externalUrls[i]!).hostname; } catch { return ""; } })();
      // A name-matched pattern (password, secret, apiKey) in a vendor's script describes the
      // vendor's widget, not this site: only vendor-format tokens are reported from third parties.
      const findings = scanContent(result.value).filter((f) => !f.pattern.firstPartyOnly || isFirstParty(pageHost, scriptHost));
      findings.forEach((f) => allExternalFindings.push({ ...f, url: externalUrls[i] }));
    }
  });

  // 3. Deduplicate findings by pattern name
  const seen = new Set<string>();
  const vulns: ScanVulnerability[] = [];

  for (const f of inlineFindings) {
    if (seen.has(f.pattern.name)) continue;
    seen.add(f.pattern.name);
    vulns.push(vuln({
      name: f.pattern.name,
      severity: f.pattern.severity,
      category: "Exposed Secrets / Credentials",
      description: f.pattern.description,
      evidence: `Source: inline <script> block\nMatch (redacted): ${redactSecret(f.match)}\nContext: ...${redactContext(f.context, f.match).slice(0, 200)}...`,
      solution: f.pattern.solution,
      cweId: f.pattern.cweId,
      cvssScore: f.pattern.cvssScore,
      wstgId: "WSTG-CONF-04",
    }));
  }

  for (const f of allExternalFindings) {
    if (seen.has(f.pattern.name)) continue;
    seen.add(f.pattern.name);
    const scriptPath = (() => { try { return new URL(f.url).pathname; } catch { return f.url; } })();
    vulns.push(vuln({
      name: f.pattern.name,
      severity: f.pattern.severity,
      category: "Exposed Secrets / Credentials",
      description: f.pattern.description,
      evidence: `Source: external script ${scriptPath}\nMatch (redacted): ${redactSecret(f.match)}\nContext: ...${redactContext(f.context, f.match).slice(0, 200)}...`,
      solution: f.pattern.solution,
      cweId: f.pattern.cweId,
      cvssScore: f.pattern.cvssScore,
      wstgId: "WSTG-CONF-04",
    }));
  }

  // 4. AI features in the site's own code (not a vendor's widget script): a provider called
  // from the browser, a system prompt in the bundle.
  const ownHost = (() => { try { return new URL(baseUrl).hostname; } catch { return ""; } })();
  const ownCode = externalContents.map((r, i) => {
    const host = (() => { try { return new URL(externalUrls[i]!).hostname; } catch { return ""; } })();
    return r.status === "fulfilled" && isFirstParty(ownHost, host) ? r.value ?? "" : "";
  });
  vulns.push(...scanAiUsage([inlineContent, ...ownCode].join(String.fromCharCode(10))));

  return vulns;
}

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
const MAX_EXTERNAL_SCRIPTS = 8;
const MAX_SCRIPT_SIZE_BYTES = 512_000; // 512 KB per file

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─────────────────────────────────────────────────────────────────────────────
// SECRET PATTERNS
// ─────────────────────────────────────────────────────────────────────────────

import { type SecretPattern, SECRET_PATTERNS } from "./secret-pattern-data";
import { isPlaceholderToken } from "./secretPlaceholders";
import { scanFetch, oncePerScan } from "./http";
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
  return [...new Set(urls)].slice(0, MAX_EXTERNAL_SCRIPTS);
}

// ─────────────────────────────────────────────────────────────────────────────
// SCAN FOR SECRETS
// ─────────────────────────────────────────────────────────────────────────────

export function redactSecret(match: string): string {
  if (match.length <= 8) return "***";
  return match.slice(0, 6) + "..." + match.slice(-4);
}

/**
 * The surrounding code shown as evidence, with every secret in it masked.
 *
 * Masking only the matched value is not enough: the context window is taken
 * around that value, so it contains it in full, and bundles tend to keep their
 * keys side by side, so it usually contains the neighbours too. A report is
 * stored, emailed and sent to the AI analysis step — the one place a live key
 * must never be written out whole.
 *
 * Three passes, each catching what the last cannot: the match itself, anything
 * any secret pattern recognises, and — as a backstop for a key cut in half at
 * the window's edge, where no pattern can match it — any long unbroken
 * token-shaped run. Over-masking a harmless identifier costs nothing here.
 */
export function redactContext(context: string, match: string): string {
  let out = context.split(match).join(redactSecret(match));
  for (const p of SECRET_PATTERNS) {
    const all = new RegExp(p.pattern.source, "g" + (p.pattern.flags.includes("i") ? "i" : ""));
    out = out.replace(all, (m) => redactSecret(m));
  }
  return out.replace(/[A-Za-z0-9+/=_-]{24,}/g, (m) => redactSecret(m));
}

/**
 * Exported so a source scan of a public GitHub repository (githubSourceProbe.ts)
 * can reuse the exact same pattern list and matching logic against fetched file
 * text, rather than duplicating it.
 */
export function scanContent(content: string): Array<{ pattern: SecretPattern; match: string; context: string }> {
  const findings: Array<{ pattern: SecretPattern; match: string; context: string }> = [];

  for (const p of SECRET_PATTERNS) {
    const globalPattern = new RegExp(p.pattern.source, "g" + (p.pattern.flags.includes("i") ? "i" : ""));
    let m: RegExpExecArray | null;
    while ((m = globalPattern.exec(content)) !== null) {
      const match = m[0];
      if (p.validate && !p.validate(match)) continue;
      // Filler in a vendor token's shape (sk_live_xxxxxxxx, ghp_0000..., Slack's documented webhook)
      // is a template, not a credential: see secretPlaceholders.ts.
      if (!p.skipPlaceholderCheck && isPlaceholderToken(match)) continue;

      // Get surrounding context (2 lines before/after)
      const start = Math.max(0, m.index - 100);
      const end = Math.min(content.length, m.index + match.length + 100);
      const context = content.slice(start, end).replace(/\n/g, " ").trim();

      findings.push({ pattern: p, match, context });
      break; // Only report once per pattern per file
    }
  }

  return findings;
}

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
  const external = await Promise.allSettled(
    extractExternalScriptUrls(html, baseUrl).map((url) => fetchScript(url)),
  );
  return [
    inline,
    ...external.map((r) => (r.status === "fulfilled" ? r.value : "")),
  ].join("\n");
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
  const own = await Promise.allSettled(
    urls.map((url) => {
      const host = (() => { try { return new URL(url).hostname; } catch { return ""; } })();
      return isFirstParty(ownHost, host) ? fetchScript(url) : Promise.resolve("");
    }),
  );
  return [extractInlineScripts(html), ...own.map((r) => (r.status === "fulfilled" ? r.value : ""))].join("\n");
}

export async function scanJavaScriptForSecrets(
  html: string,
  baseUrl: string,
): Promise<ScanVulnerability[]> {
  // 1. Scan inline scripts immediately
  const inlineContent = extractInlineScripts(html);
  const inlineFindings = scanContent(inlineContent);

  // 2. Fetch and scan external scripts in parallel
  const externalUrls = extractExternalScriptUrls(html, baseUrl);
  const externalContents = await Promise.allSettled(
    externalUrls.map((url) => fetchScript(url)),
  );

  const allExternalFindings: Array<{ pattern: SecretPattern; match: string; context: string; url: string }> = [];
  externalContents.forEach((result, i) => {
    if (result.status === "fulfilled" && result.value) {
      const findings = scanContent(result.value);
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

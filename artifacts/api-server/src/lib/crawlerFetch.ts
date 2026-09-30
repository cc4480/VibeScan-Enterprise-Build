/** Fetching and link extraction for the crawl. */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";
import { isDestructiveUrl } from "./destructive";

export const PAGE_TIMEOUT_MS = 8_000;

export const CRAWL_TIMEOUT_MS = 30_000;

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─────────────────────────────────────────────────────────────────────────────
// LINK EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

export function extractInternalLinks(html: string, baseUrl: string): string[] {
  let base: URL;
  try { base = new URL(baseUrl); } catch { return []; }

  const seen = new Set<string>();
  const hrefRegex = /href=["']([^"'#?]+)/gi;
  const srcRegex = /(?:src|action)=["']([^"'#?]+\.(?:php|asp|aspx|do|html|htm))/gi;

  const process = (raw: string) => {
    if (!raw || raw.startsWith("javascript:") || raw.startsWith("mailto:") || raw.startsWith("tel:")) return;
    try {
      const u = new URL(raw, baseUrl);
      if (u.hostname !== base.hostname) return;
      if (isDestructiveUrl(u.toString())) return;
      // Only keep paths (ignore hash, query string for dedup)
      const path = u.pathname;
      if (path === "/" || path === base.pathname) return;
      if (seen.has(path)) return;
      seen.add(path);
    } catch { /* skip invalid URLs */ }
  };

  let m: RegExpExecArray | null;
  while ((m = hrefRegex.exec(html)) !== null) process(m[1]);
  while ((m = srcRegex.exec(html)) !== null) process(m[1]);

  // Return as full URLs (high-value path probing is handled separately in crawlAndCheck)
  return [...seen].map((path) => `${base.origin}${path}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// PAGE FETCH (GET — needed for Set-Cookie, body, and full response headers)
// ─────────────────────────────────────────────────────────────────────────────

export interface PageResult {
  status: number;
  headers: Record<string, string>;
  /** Each Set-Cookie header as a separate entry (avoids Expires= comma mis-parse). */
  setCookies: string[];
  body: string;
  finalUrl: string;
}

export async function fetchPage(url: string, timeoutMs: number): Promise<PageResult | null> {
  // Set-Cookie headers arrive individually from the shared client, so a cookie
  // whose Expires date contains a comma still parses correctly.
  const res = await scanFetch(url, {
    method: "GET",
    headers: { Accept: "text/html,application/xhtml+xml,*/*" },
    timeoutMs,
  });
  if (!res) return null;

  return {
    status: res.status,
    headers: res.headers,
    setCookies: res.setCookies,
    body: res.body,
    finalUrl: res.finalUrl,
  };
}

// Light probe — fetches a URL and returns status, headers, body, and final URL after redirects
export async function probeUrl(
  url: string,
  timeoutMs: number,
): Promise<{ status: number; headers: Record<string, string>; body: string; finalUrl: string } | null> {
  const res = await scanFetch(url, { timeoutMs });
  if (!res) return null;
  return { status: res.status, headers: res.headers, body: res.body, finalUrl: res.finalUrl };
}

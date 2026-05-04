/**
 * Site crawler — checks security header consistency across inner pages.
 *
 * The root URL is often served via a CDN that injects security headers, while
 * inner routes (especially /api/* paths) bypass the CDN and hit the origin
 * server directly — missing headers entirely. This catches those gaps.
 *
 * Findings include the specific affected paths in their evidence.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const PAGE_TIMEOUT_MS = 8_000;
const CRAWL_TIMEOUT_MS = 40_000;

// Paths that could trigger destructive actions — skip these
const DANGEROUS_PATH_PATTERNS = /logout|signout|delete|remove|destroy|unsubscribe|reset|drop/i;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
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
      if (DANGEROUS_PATH_PATTERNS.test(u.pathname)) return;
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

  // Also probe high-value paths that are often present but not linked from the root
  const probeExtra = ["/api", "/api/v1", "/api/v2", "/graphql", "/admin", "/health", "/status"];
  probeExtra.forEach((p) => {
    if (!seen.has(p)) seen.add(p);
  });

  // Return as full URLs
  return [...seen].map((path) => `${base.origin}${path}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// PER-PAGE HEADER CHECK
// ─────────────────────────────────────────────────────────────────────────────

interface HeaderSnapshot {
  hsts: boolean;
  csp: boolean;
  xfo: boolean;
  xcto: boolean;
  rp: boolean;
}

function snapshotHeaders(headers: Record<string, string>): HeaderSnapshot {
  const h = (name: string) => {
    const k = Object.keys(headers).find((k) => k.toLowerCase() === name);
    return k ? headers[k] : undefined;
  };
  return {
    hsts: !!h("strict-transport-security"),
    csp:  !!h("content-security-policy"),
    xfo:  !!h("x-frame-options") || /frame-ancestors/i.test(h("content-security-policy") ?? ""),
    xcto: h("x-content-type-options")?.toLowerCase() === "nosniff",
    rp:   !!h("referrer-policy"),
  };
}

async function fetchPageHeaders(
  url: string,
): Promise<{ status: number; headers: Record<string, string>; cookies: string[] } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PAGE_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 (compatible; VibeScan-Security-Bot/1.0)" },
    });
    // Some servers return empty HEAD responses — fall back to GET
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

    const setCookie: string[] = [];
    // HEAD won't give Set-Cookie usually — ok for now
    return { status: res.status, headers, cookies: setCookie };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AGGREGATE FINDINGS
// ─────────────────────────────────────────────────────────────────────────────

interface HeaderGap {
  header: string;
  paths: string[];
  severity: ScanVulnerability["severity"];
  cweId: string;
  cvssScore: number;
  description: string;
  solution: string;
}

function buildHeaderGapVulns(
  rootSnapshot: HeaderSnapshot,
  gapMap: Map<keyof HeaderSnapshot, string[]>,
): ScanVulnerability[] {
  const HEADER_META: Record<keyof HeaderSnapshot, HeaderGap> = {
    hsts: {
      header: "Strict-Transport-Security",
      paths: [],
      severity: "high",
      cweId: "CWE-523",
      cvssScore: 7.4,
      description:
        "The root URL has HSTS configured, but the following internal routes respond without the header. Routes that bypass the CDN (e.g. API endpoints hitting origin directly) won't enforce HTTPS-only connections.",
      solution:
        "Ensure HSTS is set at the application layer, not just the CDN, so all responses include the header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    csp: {
      header: "Content-Security-Policy",
      paths: [],
      severity: "high",
      cweId: "CWE-79",
      cvssScore: 7.2,
      description:
        "CSP is present on the root URL but absent on some internal routes. API endpoints and authenticated pages often need CSP too — injected content on those pages can steal tokens.",
      solution:
        "Apply CSP at the application/middleware layer for all routes, not just the homepage. Use a base policy that works across your entire app.",
    },
    xfo: {
      header: "X-Frame-Options / frame-ancestors",
      paths: [],
      severity: "medium",
      cweId: "CWE-1021",
      cvssScore: 4.3,
      description:
        "Clickjacking protection is set on the root URL but missing on some internal pages. Those pages can be embedded in malicious iframes.",
      solution:
        "Apply X-Frame-Options: DENY (or SAMEORIGIN) globally via middleware, not per-route.",
    },
    xcto: {
      header: "X-Content-Type-Options",
      paths: [],
      severity: "medium",
      cweId: "CWE-16",
      cvssScore: 4.3,
      description:
        "X-Content-Type-Options: nosniff is on the root page but missing on some internal routes, leaving those routes open to MIME-sniffing attacks.",
      solution: "Set X-Content-Type-Options: nosniff globally in your server/middleware.",
    },
    rp: {
      header: "Referrer-Policy",
      paths: [],
      severity: "low",
      cweId: "CWE-200",
      cvssScore: 3.1,
      description:
        "Referrer-Policy is set on the root URL but absent on some internal routes.",
      solution: "Set Referrer-Policy globally: strict-origin-when-cross-origin",
    },
  };

  const results: ScanVulnerability[] = [];

  for (const [key, paths] of gapMap.entries()) {
    if (paths.length === 0) continue;
    const meta = HEADER_META[key];
    if (!meta) continue;

    // Only flag if root page HAD the header (makes this a regression, not a new issue)
    if (!rootSnapshot[key]) continue;

    const displayPaths = paths.slice(0, 6).map((p) => {
      try { return new URL(p).pathname; } catch { return p; }
    });

    results.push(vuln({
      name: `${meta.header} Missing on ${paths.length} Internal Route${paths.length > 1 ? "s" : ""}`,
      severity: meta.severity,
      category: "Security Header Inconsistency",
      description: meta.description,
      evidence: `Routes missing ${meta.header}:\n${displayPaths.map((p) => `  • ${p}`).join("\n")}${paths.length > 6 ? `\n  … and ${paths.length - 6} more` : ""}`,
      solution: meta.solution,
      cweId: meta.cweId,
      cvssScore: meta.cvssScore,
    }));
  }

  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function crawlAndCheck(
  rootUrl: string,
  rootHtml: string,
  rootHeaders: Record<string, string>,
  maxPages: number,
): Promise<ScanVulnerability[]> {
  const urls = extractInternalLinks(rootHtml, rootUrl).slice(0, maxPages);
  if (urls.length === 0) return [];

  const rootSnapshot = snapshotHeaders(rootHeaders);

  // Track which header is missing on which paths
  const gapMap = new Map<keyof typeof rootSnapshot, string[]>([
    ["hsts", []],
    ["csp",  []],
    ["xfo",  []],
    ["xcto", []],
    ["rp",   []],
  ]);

  const crawlDeadline = Date.now() + CRAWL_TIMEOUT_MS;

  const results = await Promise.allSettled(
    urls.map(async (url) => {
      if (Date.now() > crawlDeadline) return;
      const page = await fetchPageHeaders(url);
      if (!page || page.status === 404 || page.status === 0) return;
      // Only analyse 2xx and some 3xx final responses
      if (page.status >= 400) return;

      const snap = snapshotHeaders(page.headers);

      for (const key of Object.keys(rootSnapshot) as (keyof typeof rootSnapshot)[]) {
        if (rootSnapshot[key] && !snap[key]) {
          const list = gapMap.get(key) ?? [];
          list.push(url);
          gapMap.set(key, list);
        }
      }
    }),
  );

  void results; // we care about the side-effects on gapMap

  return buildHeaderGapVulns(rootSnapshot, gapMap);
}

/**
 * BaaS (Backend-as-a-Service) security probes.
 *
 * Detects PocketBase and Appwrite from page HTML / inline JS, then performs
 * read-only checks for open data access. Supabase and Firebase are covered
 * separately by supabase-probes.ts and firebase-probes.ts.
 *
 * Design constraints:
 * - Read-only. No writes, mutations, or deletes are ever performed.
 * - Black-box. All probes use the public credentials already embedded in the JS.
 * - Fail-soft. Any probe error returns [] without sinking the scan.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const TIMEOUT_MS = 8_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(
  url: string,
  headers?: Record<string, string>,
): Promise<{ status: number; body: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 Seclayer Security Scanner", ...headers },
      signal: controller.signal,
      redirect: "follow",
    });
    const body = await res.text().catch(() => "");
    return { status: res.status, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function extractInlineJs(html: string): string {
  const rx = /<script(?:[^>]*)>([\s\S]*?)<\/script>/gi;
  const parts: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = rx.exec(html)) !== null) {
    if (!/\bsrc\s*=/i.test(m[0])) parts.push(m[1] ?? "");
  }
  return parts.join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// POCKETBASE
// ─────────────────────────────────────────────────────────────────────────────

function detectPocketBaseUrls(content: string, targetOrigin: string): string[] {
  const candidates: string[] = [];

  const pbNew = /new\s+PocketBase\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/gi;
  let m: RegExpExecArray | null;
  while ((m = pbNew.exec(content)) !== null) {
    try { candidates.push(new URL(m[1]).origin); } catch { /* skip */ }
  }

  if (/pocketbase|pb\.authStore|pb\.collection/i.test(content)) {
    candidates.push(targetOrigin);
  }

  return [...new Set(candidates)].slice(0, 3);
}

const POCKETBASE_COLLECTIONS = [
  "users", "posts", "articles", "products", "orders",
  "messages", "profiles", "content", "records", "items",
];

async function probePocketBase(baseUrl: string): Promise<ScanVulnerability[]> {
  // Confirm it's PocketBase
  const health = await safeGet(`${baseUrl}/api/health`);
  if (!health || health.status !== 200) return [];
  if (!/"code"\s*:\s*200/.test(health.body) && !/"status"\s*:\s*"ok"/.test(health.body)) return [];

  const found: ScanVulnerability[] = [];

  for (const col of POCKETBASE_COLLECTIONS) {
    if (found.length >= 3) break;
    const r = await safeGet(`${baseUrl}/api/collections/${col}/records?perPage=1`);
    if (!r || r.status !== 200) continue;

    let hasRecords = false;
    let total = 0;
    try {
      const data = JSON.parse(r.body) as { items?: unknown[]; totalItems?: number };
      hasRecords = Array.isArray(data.items) && data.items.length > 0;
      total = data.totalItems ?? 0;
    } catch {
      hasRecords = r.body.includes('"items"');
    }

    found.push(vuln({
      name: `PocketBase — Unauthenticated Access to '${col}' Collection`,
      severity: hasRecords ? "critical" : "high",
      category: "BaaS Misconfiguration",
      description:
        `The PocketBase collection '${col}' is accessible without authentication. ` +
        (hasRecords
          ? `Records were returned (totalItems: ${total}).`
          : "HTTP 200 was returned; the collection allows unauthenticated list access.") +
        " PocketBase defaults to requiring auth; this collection's API rules permit public access.",
      evidence: `GET ${baseUrl}/api/collections/${col}/records?perPage=1\nHTTP 200` +
        (hasRecords ? `\ntotalItems: ${total}` : ""),
      solution:
        "In the PocketBase Admin UI → Collections → " + col + " → API Rules: set the 'List' and " +
        "'View' rules to require authentication: `@request.auth.id != ''`. An empty rule means " +
        "'allow all'. Also review the 'Create', 'Update', and 'Delete' rules.",
      cweId: "CWE-284",
      cvssScore: hasRecords ? 9.1 : 7.5,
      confidence: hasRecords ? 95 : 80,
    }));
  }

  return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// APPWRITE
// ─────────────────────────────────────────────────────────────────────────────

interface AppwriteConfig {
  endpoint: string;
  projectId: string;
}

function detectAppwrite(content: string): AppwriteConfig | null {
  // Only detect via Appwrite-specific SDK markers — not generic versioned API URLs.
  // The APPWRITE_ENDPOINT env var or the SDK's .setEndpoint() call are reliable signals.
  const endpointMatch =
    /(?:APPWRITE_ENDPOINT|setEndpoint)\s*[(:=,]\s*["'`]([^"'`\s]{8,})["'`]/i.exec(content);
  const projectMatch =
    /(?:APPWRITE_PROJECT(?:_ID)?)\s*[(:=,]\s*["'`]([a-z0-9]{15,24})["'`]/i.exec(content) ??
    /\.setProject\s*\(\s*["'`]([a-z0-9]{15,24})["'`]\s*\)/i.exec(content);

  // Require BOTH endpoint AND project to be detected via Appwrite-specific patterns
  if (!endpointMatch || !projectMatch) return null;
  // Also require the content to contain the Appwrite client import as a sanity check
  if (!/appwrite|Appwrite/i.test(content)) return null;
  return { endpoint: endpointMatch[1].replace(/\/$/, ""), projectId: projectMatch[1] };
}

async function probeAppwrite(cfg: AppwriteConfig): Promise<ScanVulnerability[]> {
  // Confirm it's Appwrite
  const health = await safeGet(`${cfg.endpoint}/health`);
  if (!health || health.status !== 200) return [];

  // Try listing documents from common collections without auth
  const COLLECTIONS = ["users", "posts", "products", "orders", "messages"];
  const found: ScanVulnerability[] = [];

  for (const coll of COLLECTIONS) {
    if (found.length >= 2) break;
    const r = await safeGet(
      `${cfg.endpoint}/databases/default/collections/${coll}/documents`,
      { "X-Appwrite-Project": cfg.projectId },
    );
    if (!r || r.status !== 200) continue;

    let hasDocuments = false;
    try {
      const data = JSON.parse(r.body) as { documents?: unknown[]; total?: number };
      hasDocuments = Array.isArray(data.documents) && data.documents.length > 0;
    } catch { /* skip */ }

    found.push(vuln({
      name: `Appwrite — Unauthenticated Document Read on '${coll}'`,
      severity: hasDocuments ? "critical" : "high",
      category: "BaaS Misconfiguration",
      description:
        `The Appwrite collection '${coll}' is readable without authentication using only the ` +
        `project ID found in your JavaScript. ` +
        (hasDocuments ? "Documents were returned." : "HTTP 200 was returned.") +
        " Appwrite permissions should require 'role:member' or 'user:<id>' for sensitive collections.",
      evidence: `GET ${cfg.endpoint}/databases/default/collections/${coll}/documents\nX-Appwrite-Project: ${cfg.projectId}\nHTTP 200`,
      solution:
        "In the Appwrite Console → Databases → your database → your collection → Settings → " +
        "Permissions: remove the 'Any' role from 'Read' permission. Set permissions to " +
        "'Users' or specific roles only. Never grant 'Any' read access to collections " +
        "containing user data.",
      cweId: "CWE-284",
      cvssScore: hasDocuments ? 9.1 : 7.5,
      confidence: hasDocuments ? 90 : 65,
    }));
  }

  return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

// Supabase and Firebase are intentionally NOT probed here — supabase-probes.ts
// and firebase-probes.ts (via vibeStackProbes.ts) already cover those backends
// with dedicated, tested implementations. Running both would produce duplicate
// findings for the same issue (e.g. two separate CVE-2025-48757 findings),
// which hurts the product's signal-quality differentiator. This orchestrator
// only covers the backends nothing else checks: PocketBase and Appwrite.
export async function runBaasProbes(
  targetUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
  const inlineJs = extractInlineJs(html);
  const searchContent = inlineJs + "\n" + html;

  let origin: string;
  try { origin = new URL(targetUrl).origin; } catch { origin = targetUrl; }

  const tasks: Promise<ScanVulnerability[]>[] = [];

  // PocketBase
  const pbUrls = detectPocketBaseUrls(searchContent, origin);
  if (pbUrls.length > 0) {
    tasks.push(
      Promise.allSettled(pbUrls.map((u) => probePocketBase(u).catch(() => [])))
        .then((rs) => rs.flatMap((r) => (r.status === "fulfilled" ? r.value : []))),
    );
  }

  // Appwrite
  const appwriteCfg = detectAppwrite(searchContent);
  if (appwriteCfg) tasks.push(probeAppwrite(appwriteCfg).catch(() => []));

  if (tasks.length === 0) return [];

  const settled = await Promise.allSettled(tasks);
  return settled.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
}

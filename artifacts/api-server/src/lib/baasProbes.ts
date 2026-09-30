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

import { classifyExposure } from "./baasExposure";
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
      headers: { "User-Agent": "Mozilla/5.0 SecScan Security Scanner", ...headers },
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

/**
 * PocketBase answers /api/health with {"code":200,"message":"API is healthy.","data":{}}.
 *
 * `{"status":"ok"}` used to be accepted here as an alternative, and a great
 * many services that are not PocketBase answer exactly that. Paired with a
 * catch-all that returns 200 for any path, it produced three High
 * "unauthenticated collection access" findings against an API with no
 * PocketBase anywhere in it.
 */
function isPocketBaseHealth(body: string): boolean {
  return /"code"\s*:\s*200/.test(body) && /"message"\s*:/.test(body);
}

/**
 * The list shape PocketBase returns: an items array alongside paging fields.
 * Requiring it means a catch-all serving HTML — or any other 200 — cannot be
 * read as an open collection.
 */
function isPocketBaseListResponse(body: string): { ok: boolean; hasRecords: boolean; total: number; items: unknown[] } {
  try {
    const data = JSON.parse(body) as { items?: unknown[]; totalItems?: number; page?: number; perPage?: number };
    const shaped =
      Array.isArray(data.items) &&
      (typeof data.totalItems === "number" || typeof data.page === "number" || typeof data.perPage === "number");
    if (!shaped) return { ok: false, hasRecords: false, total: 0, items: [] };
    const items = data.items as unknown[];
    return { ok: true, hasRecords: items.length > 0, total: data.totalItems ?? 0, items };
  } catch {
    return { ok: false, hasRecords: false, total: 0, items: [] };
  }
}

async function probePocketBase(baseUrl: string): Promise<ScanVulnerability[]> {
  // Confirm it's PocketBase
  const health = await safeGet(`${baseUrl}/api/health`);
  if (!health || health.status !== 200) return [];
  if (!isPocketBaseHealth(health.body)) return [];

  const found: ScanVulnerability[] = [];
  const emptyCols: string[] = [];

  for (const col of POCKETBASE_COLLECTIONS) {
    if (found.length >= 3) break;
    const r = await safeGet(`${baseUrl}/api/collections/${col}/records?perPage=1`);
    if (!r || r.status !== 200) continue;

    const shape = isPocketBaseListResponse(r.body);
    if (!shape.ok) continue;
    const total = shape.total;

    // An empty list is what a list rule that filters to nothing returns, as well
    // as an open rule on an empty collection: nothing was readable, so it is
    // aggregated into one INFO note rather than reported per collection.
    if (!shape.hasRecords) {
      emptyCols.push(col);
      continue;
    }
    const isPublic = classifyExposure(col, shape.items) === "public";

    found.push(vuln({
      name: isPublic
        ? `PocketBase — Public Content in '${col}' Collection Readable Without Authentication`
        : `PocketBase — Unauthenticated Access to '${col}' Collection`,
      severity: isPublic ? "info" : "critical",
      category: "BaaS Misconfiguration",
      description:
        `The PocketBase collection '${col}' returned records without authentication ` +
        `(totalItems: ${total}). ` +
        (isPublic
          ? "The name and fields look like public catalogue content with no personal or secret-looking values in the sampled record, which is normal for content the site shows every visitor; confirm it is meant to be public."
          : "PocketBase defaults to requiring auth; this collection's API rules permit public access."),
      evidence: `GET ${baseUrl}/api/collections/${col}/records?perPage=1\nHTTP 200\ntotalItems: ${total}`,
      solution:
        "In the PocketBase Admin UI → Collections → " + col + " → API Rules: set the 'List' and " +
        "'View' rules to require authentication: `@request.auth.id != ''`. An empty rule means " +
        "'allow all'. Also review the 'Create', 'Update', and 'Delete' rules.",
      cweId: isPublic ? null : "CWE-284",
      cvssScore: isPublic ? 0 : 9.1,
      confidence: isPublic ? 60 : 95,
    }));
  }

  if (emptyCols.length > 0) {
    found.push(vuln({
      name: "PocketBase — Collections Returned Empty Lists (Inconclusive)",
      severity: "info",
      category: "BaaS Misconfiguration",
      description:
        `${emptyCols.length} collection(s) answered an anonymous list request with HTTP 200 and no ` +
        "records. No data was readable. PocketBase returns this both for an open list rule on an " +
        "empty collection and for a list rule that filters every record out for anonymous users, " +
        "so it does not show a misconfiguration. Verify the List/View rules on these collections.",
      evidence: `Collections: ${emptyCols.join(", ")}\nGET ${baseUrl}/api/collections/${emptyCols[0]}/records?perPage=1 → HTTP 200, items: []`,
      solution: "Review each collection's List/View API rules in the PocketBase Admin UI.",
      cweId: null,
      cvssScore: 0,
      confidence: 40,
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
  const emptyColls: string[] = [];

  for (const coll of COLLECTIONS) {
    if (found.length >= 2) break;
    const r = await safeGet(
      `${cfg.endpoint}/databases/default/collections/${coll}/documents`,
      { "X-Appwrite-Project": cfg.projectId },
    );
    if (!r || r.status !== 200) continue;

    // Require the Appwrite list shape, so any other 200 JSON is not read as an open collection.
    let docs: unknown[] = [];
    try {
      const data = JSON.parse(r.body) as { documents?: unknown[]; total?: number };
      if (!Array.isArray(data.documents) || typeof data.total !== "number") continue;
      docs = data.documents;
    } catch { continue; }

    // Empty documents: an open rule on an empty collection and a permission
    // filter look the same. Nothing was readable, so no vulnerability finding.
    if (docs.length === 0) {
      emptyColls.push(coll);
      continue;
    }
    const isPublic = classifyExposure(coll, docs) === "public";

    found.push(vuln({
      name: isPublic
        ? `Appwrite — Public Content Readable Without Authentication on '${coll}'`
        : `Appwrite — Unauthenticated Document Read on '${coll}'`,
      severity: isPublic ? "info" : "critical",
      category: "BaaS Misconfiguration",
      description:
        `The Appwrite collection '${coll}' returned documents without authentication using only the ` +
        `project ID found in your JavaScript. ` +
        (isPublic
          ? "The name and fields look like public catalogue content with no personal or secret-looking values in the sampled documents; confirm it is meant to be public."
          : "Appwrite permissions should require 'role:member' or 'user:<id>' for sensitive collections."),
      evidence: `GET ${cfg.endpoint}/databases/default/collections/${coll}/documents\nX-Appwrite-Project: ${cfg.projectId}\nHTTP 200 with documents`,
      solution:
        "In the Appwrite Console → Databases → your database → your collection → Settings → " +
        "Permissions: remove the 'Any' role from 'Read' permission. Set permissions to " +
        "'Users' or specific roles only. Never grant 'Any' read access to collections " +
        "containing user data.",
      cweId: isPublic ? null : "CWE-284",
      cvssScore: isPublic ? 0 : 9.1,
      confidence: isPublic ? 60 : 90,
    }));
  }

  if (emptyColls.length > 0) {
    found.push(vuln({
      name: "Appwrite — Collections Returned Empty Document Lists (Inconclusive)",
      severity: "info",
      category: "BaaS Misconfiguration",
      description:
        `${emptyColls.length} collection(s) answered an anonymous list request with HTTP 200 and no ` +
        "documents. No data was readable; Appwrite returns this for an empty collection and for one " +
        "whose permissions filter everything out, so it does not show a misconfiguration.",
      evidence: `Collections: ${emptyColls.join(", ")}\nGET ${cfg.endpoint}/databases/default/collections/${emptyColls[0]}/documents → HTTP 200, documents: []`,
      solution: "Verify the collection's Read permissions in the Appwrite Console.",
      cweId: null,
      cvssScore: 0,
      confidence: 40,
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

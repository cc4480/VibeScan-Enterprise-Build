/** PocketBase detection and open-collection probing. */
import { classifyExposure } from "./baasExposure";
import type { ScanVulnerability } from "./scanner";
import { safeGet, vuln } from "./baasProbesCore";

// ─────────────────────────────────────────────────────────────────────────────
// POCKETBASE
// ─────────────────────────────────────────────────────────────────────────────

export function detectPocketBaseUrls(content: string, targetOrigin: string): string[] {
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

export const POCKETBASE_COLLECTIONS = [
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
export function isPocketBaseHealth(body: string): boolean {
  return /"code"\s*:\s*200/.test(body) && /"message"\s*:/.test(body);
}

/**
 * The list shape PocketBase returns: an items array alongside paging fields.
 * Requiring it means a catch-all serving HTML — or any other 200 — cannot be
 * read as an open collection.
 */
export function isPocketBaseListResponse(body: string): { ok: boolean; hasRecords: boolean; total: number; items: unknown[] } {
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

export async function probePocketBase(baseUrl: string): Promise<ScanVulnerability[]> {
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

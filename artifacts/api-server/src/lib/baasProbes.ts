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
import type { ScanVulnerability } from "./scanner";
import { vuln, safeGet, extractInlineJs } from "./baasProbesCore";
import { detectPocketBaseUrls, probePocketBase } from "./baasProbesPocketbase";

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
  /** Told why, when there was nothing here to test (recorded as "not tested", not "ran"). */
  notTested?: (reason: string) => void,
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

  if (tasks.length === 0) {
    notTested?.("no PocketBase or Appwrite backend is referenced in the page or its JavaScript");
    return [];
  }

  const settled = await Promise.allSettled(tasks);
  return settled.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
}
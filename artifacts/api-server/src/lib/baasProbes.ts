/**
 * BaaS (Backend-as-a-Service) security probes.
 *
 * Detects Supabase, PocketBase, Appwrite, and Firebase Firestore from
 * page HTML / inline JS, then performs read-only checks for open data access.
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
      headers: { "User-Agent": "Mozilla/5.0 VibeScan Security Scanner", ...headers },
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
// SUPABASE
// ─────────────────────────────────────────────────────────────────────────────

interface SupabaseConfig {
  url: string;
  anonKey: string;
}

function detectSupabase(content: string): SupabaseConfig | null {
  const urlMatch = /(https:\/\/[a-z0-9]+\.supabase\.co)/.exec(content);
  if (!urlMatch) return null;

  // Anon key: looks like a JWT (eyJ…)
  const keyPatterns = [
    /(?:anon|anonKey|SUPABASE_ANON_KEY|supabaseKey)\s*[:=,]\s*["'`]?(eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})["'`]?/i,
    /"(eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})"/,
  ];
  for (const rx of keyPatterns) {
    const m = rx.exec(content);
    if (m?.[1]) return { url: urlMatch[1], anonKey: m[1] };
  }
  return null;
}

const SUPABASE_TABLES = [
  "users", "profiles", "posts", "articles", "products", "orders",
  "messages", "customers", "content", "settings",
];

async function probeSupabase(cfg: SupabaseConfig): Promise<ScanVulnerability[]> {
  const headers = {
    apikey: cfg.anonKey,
    Authorization: `Bearer ${cfg.anonKey}`,
  };
  const found: ScanVulnerability[] = [];

  for (const table of SUPABASE_TABLES) {
    if (found.length >= 3) break;
    const r = await safeGet(`${cfg.url}/rest/v1/${table}?select=*&limit=1`, headers);
    if (!r || r.status !== 200) continue;

    let hasRows = false;
    try {
      const parsed = JSON.parse(r.body);
      hasRows = Array.isArray(parsed) && parsed.length > 0;
    } catch {
      hasRows = r.body.startsWith("[{");
    }

    found.push(vuln({
      name: `Supabase RLS Disabled — Unauthenticated Read on '${table}'`,
      severity: hasRows ? "critical" : "high",
      category: "BaaS Misconfiguration",
      description:
        `The Supabase table '${table}' is readable using only the public anon key, ` +
        `with no authentication required. ` +
        (hasRows
          ? "Records were returned, confirming live data exposure."
          : "HTTP 200 was returned; RLS is disabled or permits anonymous reads.") +
        " Any visitor to your site can query this table.",
      evidence: `GET ${cfg.url}/rest/v1/${table}?select=*&limit=1\napikey: <anon_key>\nHTTP ${r.status}` +
        (hasRows ? `\n${r.body.slice(0, 300)}` : ""),
      solution:
        "Enable Row Level Security (RLS) on every Supabase table: Dashboard → Table Editor → toggle " +
        "'Enable RLS'. Create policies restricting reads to authenticated users: " +
        "`CREATE POLICY reads_own ON public." + table + " FOR SELECT USING (auth.uid() = user_id);`. " +
        "Without RLS, the public anon key grants full table access.",
      cweId: "CWE-284",
      cvssScore: hasRows ? 9.1 : 7.5,
      confidence: hasRows ? 95 : 72,
    }));
  }

  return found;
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
  const endpointMatch =
    /(?:APPWRITE_ENDPOINT|setEndpoint)\s*[(:=,]\s*["'`]([^"'`]+)["'`]/i.exec(content) ??
    /(https:\/\/[^"'\s]+\/v\d)/.exec(content);
  const projectMatch =
    /(?:APPWRITE_PROJECT(?:_ID)?|setProject)\s*[(:=,]\s*["'`]([a-z0-9]{20})["'`]/i.exec(content) ??
    /setProject\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/i.exec(content);

  if (!endpointMatch || !projectMatch) return null;
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
// FIREBASE FIRESTORE
// ─────────────────────────────────────────────────────────────────────────────

interface FirebaseConfig {
  projectId: string;
  apiKey: string;
}

function detectFirebase(content: string): FirebaseConfig | null {
  // Match projectId and apiKey in any order within a config block
  const projectMatch = /projectId\s*:\s*["'`]([^"'`]+)["'`]/i.exec(content);
  const apiKeyMatch = /apiKey\s*:\s*["'`](AIza[^"'`]+)["'`]/i.exec(content);
  if (!projectMatch || !apiKeyMatch) return null;
  return { projectId: projectMatch[1], apiKey: apiKeyMatch[1] };
}

const FIRESTORE_COLLECTIONS = ["users", "posts", "messages", "orders", "profiles", "content"];

async function probeFirestore(cfg: FirebaseConfig): Promise<ScanVulnerability[]> {
  for (const col of FIRESTORE_COLLECTIONS.slice(0, 5)) {
    const url =
      `https://firestore.googleapis.com/v1/projects/${cfg.projectId}` +
      `/databases/(default)/documents/${col}?key=${cfg.apiKey}&pageSize=1`;

    const r = await safeGet(url);
    if (!r || r.status !== 200) continue;

    let hasDocuments = false;
    try {
      const data = JSON.parse(r.body) as { documents?: unknown[] };
      hasDocuments = Array.isArray(data.documents) && data.documents.length > 0;
    } catch { /* skip */ }

    return [vuln({
      name: `Firebase Firestore — Unauthenticated Read from '${col}'`,
      severity: hasDocuments ? "critical" : "high",
      category: "BaaS Misconfiguration",
      description:
        `Firestore collection '${col}' is readable without authentication using only the ` +
        `public Firebase API key found in your JavaScript. ` +
        (hasDocuments
          ? "Documents were returned, confirming live data exposure."
          : "HTTP 200 was returned; security rules permit unauthenticated reads."),
      evidence: `GET Firestore /projects/${cfg.projectId}/databases/(default)/documents/${col}\nkey: <api_key>\nHTTP 200`,
      solution:
        "Update your Firestore Security Rules to require authentication: " +
        "`match /{document=**} { allow read, write: if request.auth != null; }`. " +
        "Deploy with `firebase deploy --only firestore:rules`. " +
        "Your Firebase API key is public by design — security rules are the only access control layer.",
      cweId: "CWE-284",
      cvssScore: hasDocuments ? 9.1 : 7.5,
      confidence: hasDocuments ? 95 : 75,
    })];
  }
  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function runBaasProbes(
  targetUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
  const inlineJs = extractInlineJs(html);
  const searchContent = inlineJs + "\n" + html;

  let origin: string;
  try { origin = new URL(targetUrl).origin; } catch { origin = targetUrl; }

  const tasks: Promise<ScanVulnerability[]>[] = [];

  // Supabase
  const supabaseCfg = detectSupabase(searchContent);
  if (supabaseCfg) tasks.push(probeSupabase(supabaseCfg).catch(() => []));

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

  // Firebase
  const firebaseCfg = detectFirebase(searchContent);
  if (firebaseCfg) tasks.push(probeFirestore(firebaseCfg).catch(() => []));

  if (tasks.length === 0) return [];

  const settled = await Promise.allSettled(tasks);
  return settled.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
}

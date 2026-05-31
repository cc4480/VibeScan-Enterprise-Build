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
// SUPABASE
// ─────────────────────────────────────────────────────────────────────────────

interface SupabaseConfig {
  url: string;
  anonKey: string;
  /** Decoded JWT role claim: "anon" (public-by-design) or "service_role" (Critical). */
  jwtRole?: string;
  /** Key format: legacy JWT, or new June 2025 prefixed format. */
  keyFormat?: "legacy-jwt" | "sb-secret" | "sb-publishable";
}

/**
 * Decodes the role claim from a Supabase JWT (base64url payload).
 * Supabase JWTs include a `role` claim: "anon" or "service_role".
 * service_role carries BYPASSRLS and is a de-facto admin credential.
 */
function decodeJwtRole(token: string): string | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const padded = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(Buffer.from(padded, "base64").toString("utf-8")) as Record<string, unknown>;
    return typeof payload["role"] === "string" ? payload["role"] : null;
  } catch {
    return null;
  }
}

function detectSupabase(content: string): SupabaseConfig | null {
  // ── New key formats (Supabase June 2025+) ────────────────────────────────
  // sb_secret_* = service-role equivalent, Critical if in frontend
  const secretKeyMatch = /\b(sb_secret_[a-zA-Z0-9_-]{20,})\b/.exec(content);
  if (secretKeyMatch) {
    const urlMatch = /(https:\/\/[a-z0-9]+\.supabase\.co)/.exec(content);
    return { url: urlMatch?.[1] ?? "", anonKey: secretKeyMatch[1], keyFormat: "sb-secret" };
  }

  // sb_publishable_* = anon-key equivalent, public-by-design → Info only
  const publishableMatch = /\b(sb_publishable_[a-zA-Z0-9_-]{20,})\b/.exec(content);
  if (publishableMatch) {
    const urlMatch = /(https:\/\/[a-z0-9]+\.supabase\.co)/.exec(content);
    return { url: urlMatch?.[1] ?? "", anonKey: publishableMatch[1], keyFormat: "sb-publishable" };
  }

  // ── Legacy JWT key format ─────────────────────────────────────────────────
  const urlMatch = /(https:\/\/[a-z0-9]+\.supabase\.co)/.exec(content);
  if (!urlMatch) return null;

  // Key must be labeled with a Supabase-specific variable name — no generic JWTs
  const keyPatterns = [
    /(?:anon|anonKey|SUPABASE_ANON_KEY|supabaseKey|SUPABASE_KEY|supabase[_-]?anon)\s*[:=,]\s*["'`]?(eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})["'`]?/i,
    /createClient\s*\([^)]*["'`](https:\/\/[a-z0-9]+\.supabase\.co)["'`]\s*,\s*["'`](eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})["'`]/i,
  ];
  for (const rx of keyPatterns) {
    const m = rx.exec(content);
    let key: string | undefined;
    let url = urlMatch[1];
    if (rx.source.includes("createClient")) {
      if (m?.[2]) { key = m[2]; url = m[1] ?? url; }
    } else {
      if (m?.[1]) key = m[1];
    }
    if (!key) continue;
    const jwtRole = decodeJwtRole(key) ?? undefined;
    return { url, anonKey: key, jwtRole, keyFormat: "legacy-jwt" };
  }
  return null;
}

const SUPABASE_TABLES = [
  "users", "profiles", "posts", "articles", "products", "orders",
  "messages", "customers", "content", "settings",
];

async function probeSupabase(cfg: SupabaseConfig): Promise<ScanVulnerability[]> {
  const found: ScanVulnerability[] = [];

  // ── New key format: sb_publishable_* ─────────────────────────────────────
  // Public-by-design (equivalent to anon key). Flag as Info so the user knows
  // it was detected and is working as intended — security comes from RLS, not key secrecy.
  if (cfg.keyFormat === "sb-publishable") {
    found.push(vuln({
      name: "Supabase Publishable Key Detected (by-design)",
      severity: "info",
      category: "BaaS Configuration",
      description:
        "A Supabase publishable key (sb_publishable_…) was found in client-side JavaScript. " +
        "This is the expected format introduced in June 2025 — publishable keys are intentionally " +
        "public and identify your project. Security is enforced entirely by Row Level Security (RLS) " +
        "policies on your tables, not by keeping this key secret.",
      evidence: `Key format: sb_publishable_… detected in page JavaScript\nSupabase URL: ${cfg.url || "detected"}`,
      solution:
        "No action required for the key itself. Verify that RLS is enabled on every table in your " +
        "Supabase project (Dashboard → Table Editor → toggle 'Enable RLS') and that your policies " +
        "restrict access appropriately. Run this scan's full deep tier to check for open tables.",
      cweId: "CWE-200",
      cvssScore: 0,
      confidence: 99,
    }));
    // Still probe tables even with publishable key — RLS misconfiguration is the real risk
  }

  // ── New key format: sb_secret_* or legacy service_role JWT ────────────────
  // These bypass RLS (BYPASSRLS privilege) and are de-facto admin credentials.
  // They must NEVER appear in frontend JavaScript.
  const isServiceRole =
    cfg.keyFormat === "sb-secret" ||
    cfg.jwtRole === "service_role";

  if (isServiceRole) {
    const keyLabel = cfg.keyFormat === "sb-secret" ? "sb_secret_…" : "service_role JWT";
    found.push(vuln({
      name: "Supabase Service Role / Admin Key Exposed in Frontend",
      severity: "critical",
      category: "BaaS Misconfiguration",
      description:
        `A Supabase ${keyLabel} was found in client-side JavaScript. ` +
        "This key carries the BYPASSRLS privilege — it ignores all Row Level Security policies " +
        "and grants unrestricted read/write/delete access to every table in your database. " +
        "Anyone who visits your site has full admin access to your Supabase project.",
      evidence:
        `Key type: ${keyLabel} detected in page JavaScript\n` +
        (cfg.url ? `Supabase project: ${cfg.url}\n` : "") +
        (cfg.jwtRole === "service_role" ? "JWT role claim decoded: service_role (BYPASSRLS)" : "Key prefix: sb_secret_ (admin-tier key)"),
      solution:
        "EMERGENCY: Rotate your Supabase service role key immediately in the Supabase Dashboard → Settings → API. " +
        "Remove the key from all frontend code. " +
        "Service role keys must only be used in trusted server environments (server-side API routes, " +
        "edge functions with proper auth). Use the anon/publishable key for all client-side operations " +
        "and enforce RLS policies for access control.",
      cweId: "CWE-798",
      cvssScore: 10.0,
      confidence: 97,
    }));
  }

  // ── Table probing (behavioral confirmation) ───────────────────────────────
  // Skip table probing if we have no URL to probe
  if (!cfg.url) return found;

  const headers = {
    apikey: cfg.anonKey,
    Authorization: `Bearer ${cfg.anonKey}`,
  };

  for (const table of SUPABASE_TABLES) {
    if (found.filter((f) => f.name.startsWith("Supabase RLS")).length >= 3) break;
    const r = await safeGet(`${cfg.url}/rest/v1/${table}?select=*&limit=1`, headers);
    if (!r || r.status !== 200) continue;

    let hasRows = false;
    try {
      const parsed = JSON.parse(r.body);
      hasRows = Array.isArray(parsed) && parsed.length > 0;
    } catch {
      hasRows = r.body.startsWith("[{");
    }

    // For service_role, ALL table reads are critical (BYPASSRLS means no RLS applies at all)
    const tableBaseSeverity = isServiceRole ? "critical" : (hasRows ? "critical" : "high");

    found.push(vuln({
      name: `Supabase RLS Disabled — Unauthenticated Read on '${table}'`,
      severity: tableBaseSeverity,
      category: "BaaS Misconfiguration",
      description:
        `The Supabase table '${table}' is readable using only the public ` +
        (isServiceRole ? "service role key (BYPASSRLS — all RLS policies bypassed)" : "anon key, with no authentication required") + ". " +
        (hasRows
          ? "Records were returned, confirming live data exposure."
          : "HTTP 200 was returned; RLS is disabled or permits anonymous reads.") +
        " Any visitor to your site can query this table.",
      evidence: `GET ${cfg.url}/rest/v1/${table}?select=*&limit=1\napikey: <${isServiceRole ? "service_role" : "anon"}_key>\nHTTP ${r.status}` +
        (hasRows ? `\n${r.body.slice(0, 300)}` : ""),
      solution:
        isServiceRole
          ? "Remove the service role key from frontend code immediately (see finding above). Once fixed, " +
            "enable RLS on this table as defense-in-depth."
          : "Enable Row Level Security (RLS) on every Supabase table: Dashboard → Table Editor → toggle " +
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
// FIREBASE FIRESTORE
// ─────────────────────────────────────────────────────────────────────────────

interface FirebaseConfig {
  projectId: string;
  apiKey: string;
}

function detectFirebase(content: string): FirebaseConfig | null {
  // Require Firebase-specific config markers beyond just projectId/apiKey —
  // many non-Firebase services use those field names.
  // Firebase configs always include authDomain (<id>.firebaseapp.com) or storageBucket.
  const apiKeyMatch = /apiKey\s*:\s*["'`](AIza[A-Za-z0-9_-]{35})["'`]/i.exec(content);
  if (!apiKeyMatch) return null; // Firebase API keys always start with AIza

  const projectMatch = /projectId\s*:\s*["'`]([a-z0-9][a-z0-9-]{3,28}[a-z0-9])["'`]/i.exec(content);
  if (!projectMatch) return null;

  // Require at least one additional Firebase-specific field to confirm it's Firebase
  const hasFirebaseMarker =
    /authDomain\s*:\s*["'`][^"'`]+\.firebaseapp\.com["'`]/i.test(content) ||
    /storageBucket\s*:\s*["'`][^"'`]+\.appspot\.com["'`]/i.test(content) ||
    /messagingSenderId\s*:\s*["'`]\d{10,}["'`]/i.test(content) ||
    /firebaseio\.com/i.test(content);

  if (!hasFirebaseMarker) return null;

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

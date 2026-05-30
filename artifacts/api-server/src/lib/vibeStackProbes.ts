/**
 * Vibe-stack database security probes.
 *
 * Detects Supabase and Firebase backends from the page's JavaScript bundle,
 * then actively tests their database/storage security configuration via their
 * public REST APIs — no repository access required.
 *
 * Key vulnerability class: CVE-2025-48757 (CVSS 9.3) — 10.3% of Lovable-built
 * apps shipped with Supabase tables readable by unauthenticated requests using
 * the public anon key. The anon key is always in client-side JavaScript by
 * design; missing RLS policies are the actual vulnerability.
 *
 * Runs on both Basic and Deep tiers (no extra cost — just a handful of API
 * calls per detected backend).
 *
 * ── WRITE PROBE SAFETY ───────────────────────────────────────────────────────
 * Read tests (SELECT) are entirely non-destructive.
 *
 * Write probes (INSERT) send a body of {"__vibescan_probe__":true}.
 * This field name does not exist in any real schema, so:
 *   - 401 / 403  → auth required before schema check  → PROTECTED
 *   - 400 / 422  → auth passed, schema rejected unknown column → VULNERABLE
 *     (no row is created — PostgREST rejects the insert at schema validation)
 *   - 201        → table has zero schema constraints at all → VULNERABLE
 *     (in this case we immediately DELETE the test row by its returned id)
 *
 * We never send PATCH or DELETE against existing rows. We never use id=eq.0
 * or any heuristic that "probably matches nothing."
 *
 * Write probes are gated behind the Deep tier — Basic tier performs read
 * and informational checks only.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const TIMEOUT_MS = 10_000;
const MAX_TABLES_TO_TEST = 12;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

interface FetchResult {
  status: number;
  body: string;
  headers: Record<string, string>;
}

async function safeFetch(
  url: string,
  options: RequestInit = {},
  timeoutMs = TIMEOUT_MS,
): Promise<FetchResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    const body = await res.text().catch(() => "");
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE DETECTION
// ─────────────────────────────────────────────────────────────────────────────

interface SupabaseConfig {
  projectRef: string;
  anonKey: string;
  baseUrl: string;
}

/** Decode the role claim from a JWT without verifying the signature. */
function jwtRole(token: string): string | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as
      Record<string, unknown>;
    return typeof payload["role"] === "string" ? payload["role"] : null;
  } catch {
    return null;
  }
}

function isServiceRoleToken(token: string): boolean {
  return jwtRole(token) === "service_role";
}

/**
 * Extract the Supabase project URL and anon key from page content.
 * The anon key is designed to be public — this is NOT a vulnerability finding.
 * We need it to test the actual API endpoints.
 */
function extractSupabaseConfig(content: string): SupabaseConfig | null {
  // Find the supabase project hostname
  const urlMatch = /https?:\/\/([\w-]+)\.supabase\.co/.exec(content);
  if (!urlMatch) return null;

  const projectRef = urlMatch[1]!;
  const baseUrl = `https://${projectRef}.supabase.co`;

  // Find anon/public key — skip any service_role token
  const keyPatterns = [
    // createClient("url", "key")
    /createClient\s*\(\s*["'][^"']*["']\s*,\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/,
    // explicit variable names
    /(?:SUPABASE_ANON_KEY|SUPABASE_KEY|supabaseAnonKey|supabaseKey|anonKey|anon_key)\s*[:=]\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/i,
    // VITE / NEXT env var patterns
    /(?:VITE_SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|REACT_APP_SUPABASE_ANON_KEY)\s*[:=]\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/i,
  ];

  for (const pattern of keyPatterns) {
    const m = pattern.exec(content);
    if (m?.[1] && !isServiceRoleToken(m[1])) {
      return { projectRef, anonKey: m[1], baseUrl };
    }
  }

  // Fallback: find any eyJ JWT near the supabase URL that isn't service_role
  const urlIdx = content.indexOf(baseUrl);
  if (urlIdx !== -1) {
    const window = content.slice(urlIdx, urlIdx + 1200);
    const jwtRx = /eyJ[A-Za-z0-9._-]{40,}/g;
    let m: RegExpExecArray | null;
    while ((m = jwtRx.exec(window)) !== null) {
      if (!isServiceRoleToken(m[0])) {
        return { projectRef, anonKey: m[0], baseUrl };
      }
    }
  }

  return null;
}

/**
 * Detect the Supabase service_role key — this DOES bypass all RLS and must
 * never appear in frontend JavaScript.
 */
function extractServiceRoleKey(content: string): string | null {
  // Explicit variable names
  const explicitPatterns = [
    /(?:serviceRoleKey|service_role_key|SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE_KEY|serviceRole)\s*[:=]\s*["'](eyJ[A-Za-z0-9._-]{40,})["']/i,
  ];
  for (const p of explicitPatterns) {
    const m = p.exec(content);
    if (m?.[1] && isServiceRoleToken(m[1])) return m[1];
  }

  // Scan all JWTs and check role claim
  const jwtRx = /eyJ[A-Za-z0-9._-]{20,}\.eyJ[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]*/g;
  let m: RegExpExecArray | null;
  while ((m = jwtRx.exec(content)) !== null) {
    if (isServiceRoleToken(m[0])) return m[0];
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE LIVE API PROBES
// ─────────────────────────────────────────────────────────────────────────────

/** Hit the PostgREST OpenAPI spec to enumerate table names. */
async function enumerateSupabaseTables(
  baseUrl: string,
  anonKey: string,
): Promise<string[]> {
  const result = await safeFetch(`${baseUrl}/rest/v1/`, {
    headers: { apikey: anonKey, Accept: "application/json" },
  });
  if (!result || result.status !== 200) return [];

  try {
    const spec = JSON.parse(result.body) as {
      paths?: Record<string, unknown>;
      definitions?: Record<string, unknown>;
    };

    if (spec.paths) {
      return Object.keys(spec.paths)
        .map((p) => p.replace(/^\//, ""))
        .filter((t) => t.length > 0 && !t.includes("{") && !t.startsWith("rpc/"))
        .slice(0, MAX_TABLES_TO_TEST);
    }
    if (spec.definitions) {
      return Object.keys(spec.definitions).slice(0, MAX_TABLES_TO_TEST);
    }
  } catch { /* not valid JSON */ }

  return [];
}

type ReadResult = "open" | "empty" | "protected" | "error";

async function testTableRead(
  baseUrl: string,
  anonKey: string,
  table: string,
): Promise<ReadResult> {
  const result = await safeFetch(
    `${baseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`,
    { headers: { apikey: anonKey, Accept: "application/json" } },
    8_000,
  );
  if (!result) return "error";
  if (result.status === 401 || result.status === 403) return "protected";
  if (result.status === 200) {
    try {
      const rows = JSON.parse(result.body);
      if (Array.isArray(rows)) return rows.length > 0 ? "open" : "empty";
    } catch { /* not JSON */ }
  }
  return "error";
}

type WriteResult = "open" | "protected" | "error";

/**
 * Non-destructive INSERT probe. Sends a payload with a synthetic field name
 * that cannot exist in any real schema, so no row is ever created.
 *
 *   401 / 403  → auth is checked before schema validation → PROTECTED
 *   400 / 409 / 422 → schema rejected the field name, but auth PASSED → VULNERABLE
 *   201        → table has no NOT NULL constraints; row created; immediately cleaned up
 */
async function testTableWrite(
  baseUrl: string,
  anonKey: string,
  table: string,
): Promise<WriteResult> {
  const result = await safeFetch(
    `${baseUrl}/rest/v1/${encodeURIComponent(table)}`,
    {
      method: "POST",
      headers: {
        apikey: anonKey,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify({ __vibescan_probe__: true }),
    },
    8_000,
  );
  if (!result) return "error";

  if (result.status === 401 || result.status === 403) return "protected";

  // Schema rejected unknown column but auth passed — write access confirmed
  if (result.status === 400 || result.status === 409 || result.status === 422) return "open";

  // Row was actually inserted — clean it up immediately
  if (result.status === 201) {
    try {
      const rows = JSON.parse(result.body) as Array<Record<string, unknown>>;
      const row = (Array.isArray(rows) ? rows[0] : rows) as Record<string, unknown> | undefined;
      const id = row?.["id"] ?? row?.["ID"] ?? row?.["uuid"];
      if (id !== undefined) {
        await safeFetch(
          `${baseUrl}/rest/v1/${encodeURIComponent(table)}?id=eq.${String(id)}`,
          { method: "DELETE", headers: { apikey: anonKey } },
          5_000,
        );
      }
    } catch { /* cleanup is best-effort */ }
    return "open";
  }

  return "error";
}

async function testStorageBuckets(
  baseUrl: string,
  anonKey: string,
): Promise<boolean> {
  const result = await safeFetch(`${baseUrl}/storage/v1/bucket`, {
    headers: { apikey: anonKey, Accept: "application/json" },
  });
  if (!result || result.status !== 200) return false;
  try {
    const buckets = JSON.parse(result.body);
    return Array.isArray(buckets) && buckets.length > 0;
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FIREBASE DETECTION
// ─────────────────────────────────────────────────────────────────────────────

interface FirebaseConfig {
  apiKey: string;
  projectId: string;
  databaseURL?: string;
}

function extractFirebaseConfig(content: string): FirebaseConfig | null {
  const apiKeyPatterns = [
    /apiKey\s*:\s*["'](AIza[0-9A-Za-z\-_]{35})["']/,
    /(?:VITE_FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY|NEXT_PUBLIC_FIREBASE_API_KEY)\s*[:=]\s*["'](AIza[0-9A-Za-z\-_]{35})["']/i,
  ];
  const projectIdPatterns = [
    /projectId\s*:\s*["']([a-z0-9][a-z0-9-]{3,28}[a-z0-9])["']/,
    /(?:VITE_FIREBASE_PROJECT_ID|REACT_APP_FIREBASE_PROJECT_ID|NEXT_PUBLIC_FIREBASE_PROJECT_ID)\s*[:=]\s*["']([a-z0-9-]+)["']/i,
  ];
  const dbUrlPattern = /databaseURL\s*:\s*["'](https?:\/\/[a-z0-9-]+\.firebaseio\.com)["']/;

  let apiKey: string | null = null;
  let projectId: string | null = null;
  let databaseURL: string | undefined;

  for (const p of apiKeyPatterns) {
    const m = p.exec(content);
    if (m?.[1]) { apiKey = m[1]; break; }
  }
  for (const p of projectIdPatterns) {
    const m = p.exec(content);
    if (m?.[1]) { projectId = m[1]; break; }
  }
  const dbMatch = dbUrlPattern.exec(content);
  if (dbMatch?.[1]) databaseURL = dbMatch[1];

  if (!apiKey || !projectId) return null;
  return { apiKey, projectId, databaseURL };
}

// ─────────────────────────────────────────────────────────────────────────────
// FIREBASE LIVE API PROBES
// ─────────────────────────────────────────────────────────────────────────────

const COMMON_COLLECTIONS = [
  "users", "profiles", "accounts", "customers", "members",
  "posts", "messages", "chats", "orders", "products",
  "transactions", "payments", "config", "settings", "data",
  "records", "entries", "events", "logs", "tasks",
];

async function probeFirestoreCollection(
  projectId: string,
  apiKey: string,
  collection: string,
): Promise<boolean> {
  const url =
    `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}` +
    `/databases/(default)/documents/${encodeURIComponent(collection)}` +
    `?key=${encodeURIComponent(apiKey)}&pageSize=1`;

  const result = await safeFetch(url, { headers: { Accept: "application/json" } }, 8_000);
  if (!result || result.status !== 200) return false;

  try {
    const body = JSON.parse(result.body) as { documents?: unknown[] };
    // Empty collection returns {} or { documents: [] } — not a finding
    return Array.isArray(body.documents) && body.documents.length > 0;
  } catch {
    return false;
  }
}

async function findOpenFirestoreCollection(
  projectId: string,
  apiKey: string,
): Promise<string | null> {
  const results = await Promise.allSettled(
    COMMON_COLLECTIONS.map(async (c) => ({ c, open: await probeFirestoreCollection(projectId, apiKey, c) })),
  );
  for (const r of results) {
    if (r.status === "fulfilled" && r.value.open) return r.value.c;
  }
  return null;
}

async function testRealtimeDatabaseOpen(databaseURL: string): Promise<boolean> {
  // Unauthenticated fetch of root .json
  // Denied rules → 401, or { "error": "Permission denied." }
  const result = await safeFetch(
    `${databaseURL}/.json`,
    { headers: { Accept: "application/json" } },
    8_000,
  );
  if (!result || result.status === 401 || result.status === 403) return false;
  if (result.status !== 200) return false;

  try {
    const body = JSON.parse(result.body) as unknown;
    // null → rules are restrictive (null is the returned value for a denied read in some configs)
    // object with data → open
    return body !== null && typeof body === "object";
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function checkVibeStackSecurity(
  html: string,
  _baseUrl: string,
  tier: string,
): Promise<ScanVulnerability[]> {
  const findings: ScanVulnerability[] = [];

  // Run Supabase and Firebase probes in parallel
  const tasks: Promise<void>[] = [
    runSupabaseProbes(html, tier, findings),
    runFirebaseProbes(html, findings),
  ];

  await Promise.allSettled(tasks);
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE PROBE RUNNER
// ─────────────────────────────────────────────────────────────────────────────

async function runSupabaseProbes(
  content: string,
  tier: string,
  findings: ScanVulnerability[],
): Promise<void> {
  // ── Service role key — highest priority, both tiers ──────────────────────
  const serviceKey = extractServiceRoleKey(content);
  if (serviceKey) {
    const short = serviceKey.slice(0, 12) + "…" + serviceKey.slice(-6);
    findings.push(vuln({
      name: "Supabase Service Role Key Exposed in Client-Side Code",
      severity: "critical",
      category: "Exposed Secrets / Credentials",
      description:
        "The Supabase service_role key was found in client-side JavaScript. " +
        "Unlike the anon key — which is public by design — the service_role key " +
        "bypasses ALL Row Level Security policies on every table. Anyone who " +
        "downloads your page has full admin read/write/delete access to your " +
        "entire Supabase database. This is equivalent to shipping your database " +
        "root password in your HTML.",
      evidence:
        `Key (truncated): ${short}\n` +
        `Role claim: service_role\n` +
        "Found in: client-side JavaScript",
      solution:
        "1. Immediately rotate this key in the Supabase dashboard: " +
        "Project Settings → API → Reset service_role key.\n" +
        "2. Remove it from all frontend code.\n" +
        "3. The service_role key must only be used in server-side code " +
        "(Edge Functions, your own backend). For client-side Supabase access, " +
        "use the anon key — it is designed to be public and is safe to expose.",
      cweId: "CWE-522",
      cvssScore: 10.0,
      wstgId: "WSTG-CONF-04",
    }));
  }

  // ── Supabase API probes ───────────────────────────────────────────────────
  const config = extractSupabaseConfig(content);
  if (!config) return;

  const { projectRef, anonKey, baseUrl } = config;

  // Enumerate tables
  const tables = await enumerateSupabaseTables(baseUrl, anonKey);

  if (tables.length === 0) {
    // Supabase detected but API spec not accessible — still informational
    findings.push(vuln({
      name: "Supabase Backend Detected",
      severity: "info",
      category: "Technology Fingerprint",
      description:
        `Supabase is in use (project: ${projectRef}). The anon key is present in ` +
        "client-side JavaScript — this is expected and not a vulnerability. " +
        "No tables were enumerable via the REST API (PostgREST schema may be restricted). " +
        "Verify Row Level Security is enabled on all tables in your Supabase dashboard.",
      evidence: `Supabase URL: ${baseUrl}\nAnon key detected (public by design)`,
      solution:
        "In the Supabase SQL editor, verify RLS is enabled:\n" +
        "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';\n" +
        "Tables where rowsecurity = false are accessible to anyone with the anon key.",
      cweId: null,
      cvssScore: 0,
    }));
    return;
  }

  // Test read access on all tables
  const readResults = await Promise.allSettled(
    tables.map(async (t) => ({ table: t, result: await testTableRead(baseUrl, anonKey, t) })),
  );

  const openReadTables: string[] = [];
  const emptyOpenTables: string[] = [];

  for (const r of readResults) {
    if (r.status !== "fulfilled") continue;
    if (r.value.result === "open") openReadTables.push(r.value.table);
    if (r.value.result === "empty") emptyOpenTables.push(r.value.table);
  }

  // Test write access on open tables (Deep tier only — more invasive)
  const openWriteTables: string[] = [];
  if (tier === "deep") {
    const writeTargets = [...openReadTables, ...emptyOpenTables];
    if (writeTargets.length > 0) {
      const writeResults = await Promise.allSettled(
        writeTargets.map(async (t) => ({ table: t, result: await testTableWrite(baseUrl, anonKey, t) })),
      );
      for (const r of writeResults) {
        if (r.status === "fulfilled" && r.value.result === "open") {
          openWriteTables.push(r.value.table);
        }
      }
    }
  }

  // Report open read tables (data returned)
  if (openReadTables.length > 0) {
    findings.push(vuln({
      name: "Supabase Tables Readable Without Authentication (CVE-2025-48757)",
      severity: "critical",
      category: "Broken Access Control",
      description:
        `${openReadTables.length} Supabase table(s) return data to unauthenticated ` +
        "requests using only the public anon key. Row Level Security (RLS) is " +
        "disabled or misconfigured on these tables. This is the exact vulnerability " +
        "pattern from CVE-2025-48757 (CVSS 9.3), which exposed databases in 10.3% " +
        "of analyzed Lovable-built applications. Commonly exposed data includes: " +
        "user emails, names, passwords (plaintext in some cases), payment records, " +
        "and API keys stored as application data.",
      evidence:
        `Supabase project: ${projectRef}\n` +
        `Tables returning rows unauthenticated: ${openReadTables.join(", ")}\n` +
        `Proof: GET ${baseUrl}/rest/v1/${openReadTables[0]}?select=*&limit=1\n` +
        `Headers: apikey: <anon key> (no Authorization header)\n` +
        `Result: HTTP 200 with data rows`,
      solution:
        "Enable RLS on every affected table immediately:\n" +
        "  ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;\n\n" +
        "Add policies to restrict access to authenticated users:\n" +
        "  -- Read-only for authenticated users:\n" +
        "  CREATE POLICY \"auth_read\" ON <table_name>\n" +
        "    FOR SELECT TO authenticated USING (true);\n\n" +
        "  -- User's own rows only:\n" +
        "  CREATE POLICY \"own_data\" ON <table_name>\n" +
        "    FOR SELECT USING ((select auth.uid()) = user_id);\n\n" +
        "Important: enabling RLS without policies blocks ALL access — " +
        "add policies immediately after enabling. " +
        "Reference: https://supabase.com/docs/guides/database/postgres/row-level-security",
      cweId: "CWE-284",
      cvssScore: 9.3,
      wstgId: "WSTG-ATHZ-01",
    }));
  }

  // Report tables that are open but currently empty
  const unreportedEmptyTables = emptyOpenTables.filter((t) => !openReadTables.includes(t));
  if (unreportedEmptyTables.length > 0) {
    findings.push(vuln({
      name: "Supabase Tables Accessible Without Authentication (Currently Empty — CVE-2025-48757 Pattern)",
      severity: "high",
      category: "Broken Access Control",
      description:
        `${unreportedEmptyTables.length} Supabase table(s) respond to unauthenticated ` +
        "SELECT requests with HTTP 200. The tables are currently empty, so no data " +
        "is exposed yet — but RLS is missing and the tables will leak data the " +
        "moment any records are inserted. This is the same misconfiguration as " +
        "CVE-2025-48757.",
      evidence:
        `Tables returning HTTP 200 unauthenticated (empty): ${unreportedEmptyTables.join(", ")}\n` +
        `GET ${baseUrl}/rest/v1/${unreportedEmptyTables[0]}?select=*&limit=1 → 200 []`,
      solution:
        "Enable RLS on these tables before users create any data:\n" +
        "  ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;\n" +
        "Then add appropriate policies. Do not wait — fix this before launch.",
      cweId: "CWE-284",
      cvssScore: 7.5,
      wstgId: "WSTG-ATHZ-01",
    }));
  }

  // Report open write access (Deep tier)
  if (openWriteTables.length > 0) {
    findings.push(vuln({
      name: "Supabase Tables Accept Unauthenticated Writes",
      severity: "critical",
      category: "Broken Access Control",
      description:
        `${openWriteTables.length} Supabase table(s) accept INSERT requests from ` +
        "unauthenticated clients using only the public anon key. This allows anyone " +
        "to inject arbitrary records: fake accounts, fraudulent orders, poisoned " +
        "application data, or rows designed to exploit admin interfaces that display " +
        "user-generated content.",
      evidence:
        `Tables accepting unauthenticated writes: ${openWriteTables.join(", ")}\n` +
        `Test: POST ${baseUrl}/rest/v1/${openWriteTables[0]}\n` +
        `Headers: apikey: <anon key>, Content-Type: application/json\n` +
        `Body: {\"__vibescan_probe__\": true}\n` +
        `Result: HTTP 400/422 (schema rejected unknown column — auth was not checked)`,
      solution:
        "Enable RLS and add INSERT policies:\n" +
        "  ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;\n\n" +
        "  -- Authenticated users can insert their own rows:\n" +
        "  CREATE POLICY \"auth_insert\" ON <table_name>\n" +
        "    FOR INSERT TO authenticated\n" +
        "    WITH CHECK ((select auth.uid()) = user_id);",
      cweId: "CWE-284",
      cvssScore: 9.3,
      wstgId: "WSTG-ATHZ-01",
    }));
  }

  // Report clean tables as informational
  const allTestedTables = [...openReadTables, ...emptyOpenTables, ...openWriteTables];
  const protectedCount = tables.length - allTestedTables.length;
  if (openReadTables.length === 0 && emptyOpenTables.length === 0) {
    findings.push(vuln({
      name: "Supabase Backend Detected — RLS Appears Configured",
      severity: "info",
      category: "Technology Fingerprint",
      description:
        `Supabase is in use (project: ${projectRef}). ` +
        `${tables.length} table(s) were tested; ${protectedCount} appear auth-protected. ` +
        "No unauthenticated data access was found in common table paths. " +
        "Verify RLS policies cover edge cases: admin-only tables, service functions, " +
        "storage buckets, and any tables not enumerated here.",
      evidence: `Tables tested: ${tables.join(", ")}`,
      solution:
        "Periodically re-audit with:\n" +
        "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';\n" +
        "Any row where rowsecurity = false is unprotected.",
      cweId: null,
      cvssScore: 0,
    }));
  }

  // Storage bucket listing
  const bucketsExposed = await testStorageBuckets(baseUrl, anonKey);
  if (bucketsExposed) {
    findings.push(vuln({
      name: "Supabase Storage Bucket List Exposed Without Authentication",
      severity: "medium",
      category: "Information Disclosure",
      description:
        "The Supabase Storage API returns a list of all storage buckets to " +
        "unauthenticated requests using only the public anon key. This exposes " +
        "your storage architecture and, depending on individual bucket policies, " +
        "may allow unauthenticated read or write access to uploaded files.",
      evidence: `GET ${baseUrl}/storage/v1/bucket → HTTP 200, bucket list returned`,
      solution:
        "In the Supabase dashboard: Storage → Policies → ensure the anon role " +
        "does not have SELECT on storage.buckets unless intentional. " +
        "Restrict individual bucket policies to authenticated users where applicable.",
      cweId: "CWE-200",
      cvssScore: 5.3,
      wstgId: "WSTG-CONF-04",
    }));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FIREBASE PROBE RUNNER
// ─────────────────────────────────────────────────────────────────────────────

async function runFirebaseProbes(
  content: string,
  findings: ScanVulnerability[],
): Promise<void> {
  const config = extractFirebaseConfig(content);
  if (!config) return;

  const { apiKey, projectId, databaseURL } = config;

  // Run Firestore and Realtime DB checks in parallel
  const [firestoreOpen, rtdbOpen] = await Promise.all([
    findOpenFirestoreCollection(projectId, apiKey),
    databaseURL ? testRealtimeDatabaseOpen(databaseURL) : Promise.resolve(false),
  ]);

  if (firestoreOpen) {
    findings.push(vuln({
      name: "Firestore Security Rules Allow Unauthenticated Read Access",
      severity: "critical",
      category: "Broken Access Control",
      description:
        "Firestore is configured to allow unauthenticated read access. " +
        `Documents were returned from the '${firestoreOpen}' collection without ` +
        "any authentication. The Firebase config (apiKey, projectId) is always " +
        "present in client-side JavaScript by design — security rules are the " +
        "only access control layer. With open rules, anyone who finds your app " +
        "can read your database.",
      evidence:
        `Firebase project: ${projectId}\n` +
        `Open collection: ${firestoreOpen}\n` +
        `GET https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${firestoreOpen}?key=<apiKey> → HTTP 200 with documents`,
      solution:
        "Update your Firestore security rules to require authentication:\n\n" +
        "rules_version = '2';\n" +
        "service cloud.firestore {\n" +
        "  match /databases/{database}/documents {\n" +
        "    match /{document=**} {\n" +
        "      allow read, write: if request.auth != null;\n" +
        "    }\n" +
        "  }\n" +
        "}\n\n" +
        "For user-specific data:\n" +
        "  allow read: if request.auth.uid == resource.data.userId;\n\n" +
        "Test rules in the Firebase console Rules Playground before deploying.",
      cweId: "CWE-284",
      cvssScore: 9.3,
      wstgId: "WSTG-ATHZ-01",
    }));
  } else {
    findings.push(vuln({
      name: "Firebase Backend Detected — Firestore Rules Appear Restrictive",
      severity: "info",
      category: "Technology Fingerprint",
      description:
        `Firebase is in use (project: ${projectId}). The apiKey in client-side ` +
        "JavaScript is public by design — it identifies your project, not a secret. " +
        "No open Firestore collections were found in common collection name patterns. " +
        "Verify your rules cover all collections, including any not tested here.",
      evidence: `Project ID: ${projectId}\nFirestore: no open collections found in ${COMMON_COLLECTIONS.length} tested paths`,
      solution:
        "Audit rules in the Firebase console. Use the Rules Playground to test edge cases. " +
        "Enable App Check to restrict API access to your own app clients only.",
      cweId: null,
      cvssScore: 0,
    }));
  }

  if (rtdbOpen) {
    findings.push(vuln({
      name: "Firebase Realtime Database Open to Unauthenticated Access",
      severity: "critical",
      category: "Broken Access Control",
      description:
        "The Firebase Realtime Database returns data to unauthenticated requests " +
        "at the root path. The development default rules " +
        '({ ".read": true, ".write": true }) or equivalent permissive rules are ' +
        "active, exposing the entire database tree to anyone who knows the database URL " +
        "(which is always present in the Firebase config in client-side JavaScript).",
      evidence: `GET ${databaseURL}/.json → HTTP 200 with database contents`,
      solution:
        "Update Realtime Database rules to require authentication:\n\n" +
        "{\n" +
        '  "rules": {\n' +
        '    ".read": "auth != null",\n' +
        '    ".write": "auth != null"\n' +
        "  }\n" +
        "}\n\n" +
        "For per-user data:\n" +
        '  "users": { "$uid": { ".read": "auth.uid === $uid" } }',
      cweId: "CWE-284",
      cvssScore: 9.8,
      wstgId: "WSTG-ATHZ-01",
    }));
  }
}

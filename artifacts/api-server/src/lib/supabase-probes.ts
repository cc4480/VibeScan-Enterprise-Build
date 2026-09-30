/**
 * Supabase security probes for vibeStackProbes.ts.
 * Detects exposed Supabase backends, missing RLS policies, and service_role key exposure.
 * Extracted from vibeStackProbes.ts to reduce its size.
 */

import { randomUUID } from "node:crypto";
import { probeSupabaseAuth, probeSupabaseStorageContents } from "./baasDepth";
import type { ScanVulnerability } from "./scanner";
import { logger } from "./logger";
import { classifyExposure, rowColumns } from "./baasExposure";

const TIMEOUT_MS = 10_000;
const MAX_TABLES_TO_TEST = 12;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

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

/**
 * Table names read directly out of the page's own JavaScript, as a fallback
 * when the PostgREST root spec cannot be read.
 *
 * Supabase now restricts `GET /rest/v1/` — the OpenAPI-shaped schema listing
 * `enumerateSupabaseTables` depends on — to the service_role key. An anon key,
 * which is what ships in every frontend, gets `{"message":"Invalid API key",
 * "hint":"Only the \`service_role\` API key can be used for this endpoint."}`.
 * Verified live against a fresh project, not assumed: enumeration returns
 * empty on every current Supabase project, so this was the only path to
 * CVE-2025-48757 and it silently stopped working. The scan degraded to an INFO
 * "Supabase Backend Detected" note while a table with real, unauthenticated
 * read access sat one HTTP request away, undetected.
 *
 * The supabase-js client calls `.from("table_name")` for every table it
 * touches, and that call has to be inlined in the shipped JS bundle the same
 * way the URL and anon key are — there is no way to call it without the
 * literal name in source. This is not a guess at common table names; it is
 * reading the same bundle the anon key itself was extracted from for the
 * tables the app's own code actually names.
 */
function extractTableNamesFromContent(content: string): string[] {
  const names = new Set<string>();
  // .from("table"), .from('table'), .from(`table`) — optional TS generic
  // between .from and the parenthesis, e.g. .from<Database>("table").
  const rx = /\.from\s*(?:<[^>()]*>)?\s*\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]*)["'`]\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(content)) !== null) {
    if (m[1]) names.add(m[1]);
  }
  return [...names].slice(0, MAX_TABLES_TO_TEST);
}

type ReadResult =
  | { kind: "open"; rows: unknown[] }
  | { kind: "empty" | "protected" | "error" };

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
  if (!result) return { kind: "error" };
  if (result.status === 401 || result.status === 403) return { kind: "protected" };
  if (result.status === 200) {
    try {
      const rows = JSON.parse(result.body);
      if (Array.isArray(rows)) {
        return rows.length > 0 ? { kind: "open", rows } : { kind: "empty" };
      }
    } catch { /* not JSON */ }
  }
  return { kind: "error" };
}

/**
 * "open" only on an unambiguous 2xx. "unconfirmed" is a 400/409/422, which
 * proves nothing about access (see testTableWrite).
 */
type WriteResult =
  | { kind: "open" }
  | { kind: "unconfirmed"; status: number; code: string }
  | { kind: "protected" | "error" };

/**
 * Non-destructive INSERT probe. Sends a payload with a synthetic field name
 * that cannot exist in any real schema, so on a table with any NOT NULL column
 * the write is rejected before a row exists. A table with no such constraint
 * does accept it, which is the 201 case below: the row is real and is deleted
 * again immediately.
 *
 *   401 / 403  → RLS rejected the insert → PROTECTED
 *   400 / 409 / 422 → UNCONFIRMED. This used to be read as "auth passed, schema
 *     rejected the field" and reported CRITICAL, but PostgREST validates the
 *     body's columns against its schema cache (PGRST204 "Could not find the
 *     column") before the statement reaches Postgres, so a table with RLS on
 *     answers 400 here exactly like an unprotected one. Not verified against a
 *     live server, so this is reported as an inconclusive INFO, never as open.
 *   2xx        → row created (this branch cleans it up) → OPEN
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
  if (!result) return { kind: "error" };

  if (result.status === 401 || result.status === 403) return { kind: "protected" };

  if (result.status === 400 || result.status === 409 || result.status === 422) {
    let code = "";
    try { code = String((JSON.parse(result.body) as { code?: unknown }).code ?? ""); } catch { /* not JSON */ }
    return { kind: "unconfirmed", status: result.status, code };
  }

  // Row was actually inserted — clean it up immediately.
  //
  // The filter column has to be the one the key was actually read FROM. This
  // used to read the value from id/ID/uuid and then always delete with
  // "?id=eq.", so a table keyed on "uuid" filtered a column that need not
  // exist (PostgREST rejects it, row survives), and a table keyed on anything
  // else — user_id, pk, slug, a composite — found no value at all and skipped
  // the DELETE entirely while still reporting "open". Both left a row behind in
  // someone else's database, against a promise we make publicly.
  if (result.status >= 200 && result.status < 300) {
    let deleted = false;
    try {
      const rows = JSON.parse(result.body) as Array<Record<string, unknown>>;
      const row = (Array.isArray(rows) ? rows[0] : rows) as Record<string, unknown> | undefined;
      const keyColumn = ["id", "ID", "uuid", "uid"].find(
        (c) => row?.[c] !== undefined && row[c] !== null,
      );
      const id = keyColumn ? row?.[keyColumn] : undefined;

      if (keyColumn && (typeof id === "string" || typeof id === "number")) {
        const del = await safeFetch(
          `${baseUrl}/rest/v1/${encodeURIComponent(table)}` +
            `?${encodeURIComponent(keyColumn)}=eq.${encodeURIComponent(String(id))}`,
          { method: "DELETE", headers: { apikey: anonKey } },
          5_000,
        );
        deleted = del !== null && del.status >= 200 && del.status < 300;
      }
    } catch { /* fall through to the warning below */ }

    // A row we could not remove is the one outcome here nobody must find out
    // about from the customer. Louder than a silent best-effort catch.
    if (!deleted) {
      logger.warn(
        { table },
        "Supabase write probe created a row it could not delete — manual cleanup may be needed",
      );
    }
    return { kind: "open" };
  }

  return { kind: "error" };
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

// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE PROBE RUNNER
// ─────────────────────────────────────────────────────────────────────────────

export async function runSupabaseProbes(
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

  await probeSupabaseAuth(baseUrl, anonKey, findings);
  await probeSupabaseStorageContents(baseUrl, anonKey, findings);

  // Enumerate tables. The REST schema listing is the more complete source
  // when it works, but Supabase now restricts it to service_role on new
  // projects (see extractTableNamesFromContent), so the bundle's own .from()
  // calls fill the gap rather than being an either/or with it.
  const specTables = await enumerateSupabaseTables(baseUrl, anonKey);
  const bundleTables = extractTableNamesFromContent(content);
  const tables = [...new Set([...specTables, ...bundleTables])].slice(0, MAX_TABLES_TO_TEST);

  if (tables.length === 0) {
    // Supabase detected but no table name could be found by either route —
    // still informational, not a finding about the tables themselves, because
    // there is nothing here to test read access against.
    findings.push(vuln({
      name: "Supabase Backend Detected",
      severity: "info",
      category: "Technology Fingerprint",
      description:
        `Supabase is in use (project: ${projectRef}). The anon key is present in ` +
        "client-side JavaScript — this is expected and not a vulnerability. " +
        "No table names were found, either via the REST API schema (now restricted " +
        "to the service_role key on most projects) or in the page's own JavaScript. " +
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

  const openReadTables: string[] = [];      // rows of sensitive/unclassified tables
  const publicReadTables: string[] = [];    // rows of public-catalogue tables
  const emptyTables: string[] = [];
  const publicColumns = new Map<string, string>();

  for (const r of readResults) {
    if (r.status !== "fulfilled") continue;
    const { table, result } = r.value;
    if (result.kind === "empty") emptyTables.push(table);
    if (result.kind !== "open") continue;
    if (classifyExposure(table, result.rows) === "public") {
      publicReadTables.push(table);
      publicColumns.set(table, rowColumns(result.rows));
    } else {
      openReadTables.push(table);
    }
  }

  // Test write access on every table that answered the read. This is the most
  // invasive thing the scanner does — it attempts an actual insert against the
  // target's database — and it used to be reserved for the deep tier. With one
  // tier it runs on every scan.
  const openWriteTables: string[] = [];
  const unconfirmedWrites: Array<{ table: string; status: number; code: string }> = [];
  {
    const writeTargets = [...openReadTables, ...publicReadTables, ...emptyTables];
    if (writeTargets.length > 0) {
      const writeResults = await Promise.allSettled(
        writeTargets.map(async (t) => ({ table: t, result: await testTableWrite(baseUrl, anonKey, t) })),
      );
      for (const r of writeResults) {
        if (r.status !== "fulfilled") continue;
        const w = r.value.result;
        if (w.kind === "open") openWriteTables.push(r.value.table);
        if (w.kind === "unconfirmed") {
          unconfirmedWrites.push({ table: r.value.table, status: w.status, code: w.code });
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
      confidence: 90,
    }));
  }

  // Public-catalogue tables: rows came back, but the table looks like content
  // the app shows every visitor anyway (products, posts, pricing...) with no
  // personal or secret-looking columns. Observed, not a vulnerability by itself.
  if (publicReadTables.length > 0) {
    findings.push(vuln({
      name: "Supabase Public Content Tables Readable Without Authentication",
      severity: "info",
      category: "Information Disclosure",
      description:
        `${publicReadTables.length} Supabase table(s) return rows to the public anon key, but ` +
        "their names and columns look like public catalogue content (products, posts, " +
        "pricing and similar) with no personal or secret-looking fields in the sampled " +
        "row. That is normal for content the site shows every visitor, so this is not " +
        "reported as a vulnerability. Confirm the tables are meant to be public and " +
        "hold no draft, hidden or per-user rows.",
      evidence:
        `Tables: ${publicReadTables.join(", ")}\n` +
        `Sampled columns (${publicReadTables[0]}): ${publicColumns.get(publicReadTables[0]!) ?? ""}\n` +
        `GET ${baseUrl}/rest/v1/${publicReadTables[0]}?select=*&limit=1 → HTTP 200 with rows`,
      solution:
        "If any of these tables should not be public, enable RLS and add a SELECT policy. " +
        "For intentionally public content, restrict the policy to published rows " +
        "(e.g. USING (published = true)) and keep write policies authenticated-only.",
      cweId: null,
      cvssScore: 0,
      confidence: 60,
    }));
  }

  // Tables that answered 200 with an empty array. PostgREST answers exactly
  // that for a table with RLS ENABLED and no anon SELECT policy (the correct,
  // protected configuration) as well as for an unprotected empty table, so the
  // response cannot distinguish them and proves nothing was readable.
  if (emptyTables.length > 0) {
    findings.push(vuln({
      name: "Supabase Tables Returned Empty Results To Anonymous Requests (Inconclusive)",
      severity: "info",
      category: "Broken Access Control",
      description:
        `${emptyTables.length} Supabase table(s) answered an anonymous SELECT with HTTP 200 and ` +
        "an empty array. No data was readable. PostgREST returns this both for a table with " +
        "Row Level Security enabled and no anon policy (correctly protected) and for an " +
        "empty table without RLS, so this is not evidence of a misconfiguration. It is " +
        "listed so you can confirm RLS is enabled on these tables.",
      evidence:
        `Tables: ${emptyTables.join(", ")}\n` +
        `GET ${baseUrl}/rest/v1/${emptyTables[0]}?select=*&limit=1 → 200 []`,
      solution:
        "Confirm RLS is enabled: SELECT tablename, rowsecurity FROM pg_tables " +
        "WHERE schemaname = 'public'; a table with rowsecurity = false will expose rows " +
        "to the anon key as soon as it holds data.",
      cweId: null,
      cvssScore: 0,
      confidence: 40,
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
        `Result: HTTP 2xx (the insert was accepted; the probe row was then deleted)`,
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
      confidence: 90,
    }));
  }

  // 400/409/422 to the write probe: PostgREST rejects the unknown column
  // before RLS is evaluated, so this neither proves nor rules out write access.
  const ambiguousOnly = unconfirmedWrites.filter((w) => !openWriteTables.includes(w.table));
  if (ambiguousOnly.length > 0) {
    findings.push(vuln({
      name: "Supabase Write Access Not Confirmed (Inconclusive Probe Response)",
      severity: "info",
      category: "Broken Access Control",
      description:
        `An anonymous INSERT probe to ${ambiguousOnly.length} table(s) was rejected with a ` +
        "400/409/422 validation error rather than 401/403 or success. PostgREST validates " +
        "the request body against its schema before Row Level Security is evaluated, so " +
        "this response does not show whether anonymous inserts are allowed. No row was " +
        "created. Verify that INSERT policies on these tables require authentication.",
      evidence:
        ambiguousOnly.map((w) => `${w.table}: HTTP ${w.status}${w.code ? ` (${w.code})` : ""}`).join("\n"),
      solution:
        "Review INSERT policies: SELECT tablename, policyname, cmd, roles, with_check " +
        "FROM pg_policies WHERE schemaname = 'public' AND cmd IN ('INSERT', 'ALL'); " +
        "any policy granting anon/public with WITH CHECK (true) allows anonymous writes.",
      cweId: null,
      cvssScore: 0,
      confidence: 30,
    }));
  }

  // Report clean tables as informational
  const allTestedTables = [...openReadTables, ...publicReadTables, ...emptyTables];
  const protectedCount = tables.length - allTestedTables.length;
  if (openReadTables.length === 0 && publicReadTables.length === 0 && emptyTables.length === 0) {
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

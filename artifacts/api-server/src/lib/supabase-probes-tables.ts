import type { TableProbeResults } from "./supabase-probes-report";
import { logger } from "./logger";
import { safeFetch, MAX_TABLES_TO_TEST } from "./supabase-probes-core";
import { classifyExposure, rowColumns } from "./baasExposure";

/** Table discovery and the anonymous read/write/storage tests against them. */



// ─────────────────────────────────────────────────────────────────────────────
// SUPABASE LIVE API PROBES
// ─────────────────────────────────────────────────────────────────────────────

/** Hit the PostgREST OpenAPI spec to enumerate table names. */
export async function enumerateSupabaseTables(
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
export function extractTableNamesFromContent(content: string): string[] {
  const names = new Set<string>();
  // .from("table"), .from('table'), .from(`table`) — optional TS generic
  // between .from and the parenthesis, e.g. .from<Database>("table").
  //
  // Not `.storage.from("bucket")`, which names a storage bucket, and not the built-in
  // `Array.from("…")` / `Buffer.from("…")` of the library code a bundle carries: in a whole bundle
  // those would take the places of real tables in the short list that gets probed.
  const rx = /(?<!\.storage\s*|\b(?:Array|Buffer|Int8Array|Uint8Array|Uint16Array|Uint32Array|Float32Array|Float64Array)\s*)\.from\s*(?:<[^>()]*>)?\s*\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]*)["'`]\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(content)) !== null) {
    if (m[1]) names.add(m[1]);
  }
  return [...names].slice(0, MAX_TABLES_TO_TEST);
}

/**
 * Storage bucket names the app's own code opens: `supabase.storage.from("avatars")`. The bucket list
 * endpoint answers an empty list to the anon key unless a policy allows it, so a public bucket whose
 * files can be listed is only found by naming it, and the code is where its name is written. The
 * `.storage` property is not renamed by a minifier.
 */
export function extractStorageBucketNames(content: string): string[] {
  const names = new Set<string>();
  for (const m of content.matchAll(/\.storage\s*\.from\s*\(\s*["'`]([A-Za-z0-9][A-Za-z0-9._-]{0,62})["'`]\s*\)/g)) {
    if (m[1]) names.add(m[1]);
    if (names.size >= 10) break;
  }
  return [...names];
}

export type ReadResult =
  | { kind: "open"; rows: unknown[] }
  | { kind: "empty" | "protected" | "error" };

export async function testTableRead(
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
export type WriteResult =
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
export async function testTableWrite(
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

export async function testStorageBuckets(
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

/** Tests anonymous read on every table, then write on every table that answered the read. */
export async function probeTables(baseUrl: string, anonKey: string, tables: string[]): Promise<TableProbeResults> {
  // Test read access on all tables
  const readResults = await Promise.allSettled(
    tables.map(async (t) => ({ table: t, result: await testTableRead(baseUrl, anonKey, t) })),
  );

  const openReadTables: string[] = [];      // rows of sensitive (personal, secret, per-user) tables
  const publicReadTables: string[] = [];    // rows of public-catalogue tables
  const unclassifiedReadTables: string[] = []; // rows that nothing marks as either
  const emptyTables: string[] = [];
  const publicColumns = new Map<string, string>();

  for (const r of readResults) {
    if (r.status !== "fulfilled") continue;
    const { table, result } = r.value;
    if (result.kind === "empty") emptyTables.push(table);
    if (result.kind !== "open") continue;
    const exposure = classifyExposure(table, result.rows);
    if (exposure === "public") {
      publicReadTables.push(table);
      publicColumns.set(table, rowColumns(result.rows));
    } else if (exposure === "unclassified") {
      unclassifiedReadTables.push(table);
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
    const writeTargets = [...openReadTables, ...publicReadTables, ...unclassifiedReadTables, ...emptyTables];
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
  return { openReadTables, publicReadTables, unclassifiedReadTables, emptyTables, publicColumns, openWriteTables, unconfirmedWrites };
}

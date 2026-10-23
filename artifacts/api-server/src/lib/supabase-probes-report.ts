import { vuln } from "./supabase-probes-core";
import { extractServiceRoleKey } from "./supabase-probes-config";
import type { ScanVulnerability } from "./scanner";

/** What the Supabase check calls a service_role key it found in the page or its scripts. */
export const SERVICE_ROLE_FROM_CHECK = "Supabase Service Role Key Exposed in Client-Side Code";
/** What the secret scanner calls the same key (it also says which script held it). */
export const SERVICE_ROLE_FROM_SCRIPTS = "Supabase Service Role Key Exposed in JavaScript";

/**
 * The secret scanner and the Supabase check each find a leaked service_role key, now that both read the
 * bundle, and each reports it. One key is one finding: when the scanner has it (and it says which script
 * held it), the check's copy is dropped.
 */
export function withoutRepeatedServiceRole(fromCheck: ScanVulnerability[], fromScripts: ScanVulnerability[]): ScanVulnerability[] {
  return fromScripts.some((f) => f.name === SERVICE_ROLE_FROM_SCRIPTS)
    ? fromCheck.filter((f) => f.name !== SERVICE_ROLE_FROM_CHECK)
    : fromCheck;
}

/** A service-role key in client code bypasses Row Level Security entirely. */
export function reportServiceRoleKey(content: string, findings: ScanVulnerability[]): void {
  const serviceKey = extractServiceRoleKey(content);
  if (serviceKey) {
    const short = serviceKey.slice(0, 12) + "…" + serviceKey.slice(-6);
    findings.push(vuln({
      name: SERVICE_ROLE_FROM_CHECK,
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
}

/** What the anonymous read and write tests found across the tables. */
export interface TableProbeResults {
  /** Tables whose rows are personal, secret or per-user (or whose class could not be told, in older callers). */
  openReadTables: string[];
  publicReadTables: string[];
  /** Tables that returned rows but whose name and sampled columns say neither public nor sensitive. */
  unclassifiedReadTables?: string[];
  emptyTables: string[];
  publicColumns: Map<string, string>;
  openWriteTables: string[];
  unconfirmedWrites: Array<{ table: string; status: number; code: string }>;
}

/** Turns the table probe results into findings. */
export function reportTableFindings(
  results: TableProbeResults & { tables: string[]; projectRef: string; baseUrl: string },
  findings: ScanVulnerability[],
): void {
  const { openReadTables, publicReadTables, emptyTables, publicColumns, openWriteTables, unconfirmedWrites, tables, projectRef, baseUrl } = results;
  const unclassifiedReadTables = results.unclassifiedReadTables ?? [];
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

  // Rows came back, and nothing in the table's name or the sampled row says they are personal, secret or
  // per-user (no email, token, password or owner column such as user_id), nor that they are catalogue
  // content. That is a question for the owner, not a vulnerability: a table of announcements, a changelog or a
  // list of countries looks exactly like this, and so does a table that should have been locked.
  if (unclassifiedReadTables.length > 0) {
    findings.push(vuln({
      name: "Supabase Tables Readable Without Authentication (Not Classified)",
      severity: "info",
      category: "Broken Access Control",
      description:
        `${unclassifiedReadTables.length} Supabase table(s) return rows to the public anon key. Their names and the ` +
        "columns of the sampled row do not mark them as personal, secret or per-user data (no email, token, " +
        "password or owner column such as user_id), so this is not reported as a vulnerability, and nothing marks " +
        "them as public catalogue content either. Whether anyone should be able to read them depends on what " +
        "they hold. Confirm that each is meant to be readable by every visitor and that no draft, hidden or " +
        "per-user rows are in it.",
      evidence:
        `Tables: ${unclassifiedReadTables.join(", ")}\n` +
        `Sampled columns (${unclassifiedReadTables[0]}): ${publicColumns.get(unclassifiedReadTables[0]!) ?? ""}\n` +
        `GET ${baseUrl}/rest/v1/${unclassifiedReadTables[0]}?select=*&limit=1 → HTTP 200 with rows`,
      solution:
        "If any of these tables should not be public, enable RLS and add a SELECT policy. " +
        "For intentionally public content, restrict the policy to published rows " +
        "(e.g. USING (published = true)) and keep write policies authenticated-only.",
      cweId: null,
      cvssScore: 0,
      confidence: 40,
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
}

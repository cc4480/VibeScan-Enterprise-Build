/** Supabase row-level-security probe. */
import type { ScanVulnerability } from "./scanner";
import { classifyExposure } from "./baasExposure";
import { extractSupabaseConfig } from "./supabase-probes-config";
import { vuln, safeGet } from "./probesCore";
import { supabaseProjectOrigin } from "./baasEndpoints";

// ─────────────────────────────────────────────────────────────────────────────
// 13. SUPABASE ROW LEVEL SECURITY CHECK
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Tests whether a Supabase-backed application has Row Level Security (RLS)
 * properly configured on its database tables.
 *
 * Detection approach:
 *   1. Find the Supabase project URL in the page HTML and in the site's own JavaScript.
 *   2. Extract the anon/publishable key written next to it (a bundle keeps both as string constants).
 *   3. Call the Supabase REST API with only that key to enumerate table names.
 *   4. Query each discovered table — if rows come back, RLS is disabled.
 *
 * Context: 83% of Supabase exposures involve RLS misconfiguration (Escape.tech, Feb 2026).
 * CVE-2025-48757 (Lovable breach) was caused by exactly this pattern — ~10% of all
 * Lovable-hosted apps had fully open tables leaking plaintext credentials.
 */
export async function checkSupabaseRLS(
  /** The page, or the page plus the site's own scripts (a promise while those are still downloading). */
  page: string | Promise<string>,
  /** Told why nothing was tested, so the report says "not tested" rather than "ran, 0 findings". */
  notTested?: (reason: string) => void,
): Promise<ScanVulnerability[]> {
  const html = await page;

  // 1. Find the Supabase project and its public key. The shared extractor reads a first-party bundle
  //    as well as a page (a production build keeps both as renamed string constants), and never
  //    returns the service_role key or a key issued for another project.
  const config = extractSupabaseConfig(html);
  const projectRef = config?.projectRef ?? /https:\/\/([a-z0-9]{20})\.supabase\.co/.exec(html)?.[1];
  if (!projectRef || !/^[a-z0-9]{20}$/.test(projectRef)) {
    notTested?.("No Supabase project was found in the page, so there was no database to test.");
    return [];
  }

  const supabaseOrigin = supabaseProjectOrigin(projectRef);
  const restBase = `${supabaseOrigin}/rest/v1/`;

  // 2. The anon/publishable key (a sb_publishable_ key or the legacy JWT). A bare token that merely
  //    appears somewhere in a page or bundle is not taken as the key: it could be any JWT.
  const anonKey: string | null = config && config.projectRef === projectRef ? config.anonKey : null;

  if (!anonKey) {
    // Supabase detected but key is in a lazy-loaded bundle — advise manual check
    // Nothing was observed here — no key, no request — so this is a pointer to
    // check, not a finding about the customer's database: INFO, low confidence.
    return [vuln({
      name: "Supabase Detected — Verify Row Level Security (RLS)",
      severity: "info",
      category: "Database Security",
      description: "A Supabase backend was detected, but its public key could not be read from the page, so no table was tested. Nothing here shows a misconfiguration. Row Level Security (RLS) is the access control for Supabase data (CVE-2025-48757 affected apps that left it off), so it is worth confirming it is enabled on every table that holds non-public data.",
      evidence: `Supabase project detected: ${supabaseOrigin}\nThe anon key could not be read from the page or its first-party JavaScript — it may be in a lazy-loaded chunk. No request was made to the project.`,
      solution: "In Supabase Dashboard → Table Editor, confirm RLS is enabled on every table with non-public data (users, profiles, orders, payments). Test by hitting your REST API with just the anon key — you should get 0 rows or a 403 for those tables.",
      cweId: null,
      cvssScore: 0,
      wstgId: "WSTG-ATHZ-01",
      confidence: 30,
    })];
  }

  const authHeaders = {
    "apikey": anonKey,
    "Authorization": `Bearer ${anonKey}`,
    "Accept": "application/json",
  };

  // 3. Get table names from the OpenAPI schema endpoint
  const schemaRes = await safeGet(restBase, { headers: authHeaders });
  if (!schemaRes || schemaRes.status !== 200) {
    notTested?.(`The Supabase table list could not be read with the public key (${schemaRes ? `HTTP ${schemaRes.status}` : "no response"}), so no table was queried.`);
    return [];
  }

  let tableNames: string[] = [];
  try {
    const schema = JSON.parse(schemaRes.body) as {
      definitions?: Record<string, unknown>;
      paths?: Record<string, unknown>;
    };
    if (schema.definitions) {
      tableNames = Object.keys(schema.definitions).slice(0, 8);
    } else if (schema.paths) {
      tableNames = Object.keys(schema.paths)
        .map((p) => p.replace(/^\//, ""))
        .filter((t) => t && !t.includes("/") && !t.startsWith("rpc"))
        .slice(0, 8);
    }
  } catch { return []; }

  if (tableNames.length === 0) return [];

  // 4. Query each table with the anon key — any 200 with rows = RLS is off
  const exposedTables: string[] = [];
  const publicTables: string[] = [];
  const unclassifiedTables: string[] = [];
  await Promise.allSettled(
    tableNames.map(async (table) => {
      const tableUrl = `${restBase}${encodeURIComponent(table)}?select=*&limit=1`;
      const res = await safeGet(tableUrl, {
        headers: { ...authHeaders, "Prefer": "count=none" },
      });
      if (res?.status === 200) {
        try {
          const rows = JSON.parse(res.body);
          if (Array.isArray(rows) && rows.length > 0) {
            // Rows from a public catalogue (products, posts...) are not RLS-off, and rows that nothing
            // marks as personal, secret or per-user are a question for the owner, not a critical finding.
            const exposure = classifyExposure(table, rows);
            (exposure === "public" ? publicTables : exposure === "unclassified" ? unclassifiedTables : exposedTables).push(table);
          }
        } catch { /* not JSON */ }
      }
    }),
  );

  if (exposedTables.length > 0) {
    return [vuln({
      name: "Supabase Tables Exposed — Row Level Security (RLS) Disabled",
      severity: "critical",
      category: "Database Security",
      description: `${exposedTables.length} database table(s) returned data to an unauthenticated request using only the public anon key: ${exposedTables.join(", ")}. Anyone who visits this site can read — and possibly write — this data directly via the Supabase REST API, bypassing your app entirely. This is the #1 database vulnerability in AI-generated apps.`,
      evidence: `Supabase project: ${supabaseOrigin}\nExposed tables (responded with rows, no auth): ${exposedTables.join(", ")}\nGET ${restBase}${exposedTables[0]}?select=*&limit=1 → HTTP 200 with data (anon key only)`,
      solution: "EMERGENCY: Go to Supabase Dashboard → Table Editor → select each table → Auth Policies → turn on Row Level Security. Then add a policy like: (auth.uid() = user_id) for SELECT. Do this for ALL tables. Test: query the table with just your anon key (no login) — it should return empty or 403, not your data. See: https://supabase.com/docs/guides/auth/row-level-security",
      cweId: "CWE-862",
      cvssScore: 9.8,
      wstgId: "WSTG-ATHZ-01",
      confidence: 90,
    })];
  }

  // Only public-catalogue tables (products, posts...) answered with rows: that is
  // what the storefront shows every visitor, not "RLS disabled". Observed
  // fact, reported as INFO for the owner to confirm.
  const notes: ScanVulnerability[] = [];
  if (publicTables.length > 0) {
    notes.push(vuln({
      name: "Supabase Public Content Tables Readable Without Authentication",
      severity: "info",
      category: "Database Security",
      description: `${publicTables.length} table(s) returned rows to the public anon key (${publicTables.join(", ")}), but they look like public catalogue content with no personal or secret-looking fields in the sampled row. This is normal for content the site shows every visitor; confirm the tables are meant to be public and hold no hidden or per-user rows.`,
      evidence: `Supabase project: ${supabaseOrigin}\nGET ${restBase}${publicTables[0]}?select=*&limit=1 → HTTP 200 with rows (anon key only)`,
      solution: "If any of these tables should not be public, enable RLS and add a SELECT policy limited to published rows.",
      cweId: null,
      cvssScore: 0,
      wstgId: "WSTG-ATHZ-01",
      confidence: 60,
    }));
  }

  // Rows came back and nothing says whose they are or that they are secret: the same note the
  // table probe raises (see reportTableFindings), at the same severity.
  if (unclassifiedTables.length > 0) {
    notes.push(vuln({
      name: "Supabase Tables Readable Without Authentication (Not Classified)",
      severity: "info",
      category: "Database Security",
      description: `${unclassifiedTables.length} table(s) returned rows to the public anon key (${unclassifiedTables.join(", ")}). Their names and the sampled row do not mark them as personal, secret or per-user data (no email, token, password or owner column such as user_id), so this is not reported as a vulnerability, and nothing marks them as public catalogue content either. Confirm they are meant to be readable by every visitor and hold no hidden or per-user rows.`,
      evidence: `Supabase project: ${supabaseOrigin}\nGET ${restBase}${unclassifiedTables[0]}?select=*&limit=1 → HTTP 200 with rows (anon key only)`,
      solution: "If any of these tables should not be public, enable RLS and add a SELECT policy limited to published rows.",
      cweId: null,
      cvssScore: 0,
      wstgId: "WSTG-ATHZ-01",
      confidence: 40,
    }));
  }

  return notes;
}

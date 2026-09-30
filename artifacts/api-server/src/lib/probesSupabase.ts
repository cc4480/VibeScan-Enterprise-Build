/** Supabase row-level-security probe. */
import type { ScanVulnerability } from "./scanner";
import { classifyExposure } from "./baasExposure";
import { vuln, safeGet } from "./probesCore";

// ─────────────────────────────────────────────────────────────────────────────
// 13. SUPABASE ROW LEVEL SECURITY CHECK
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Tests whether a Supabase-backed application has Row Level Security (RLS)
 * properly configured on its database tables.
 *
 * Detection approach:
 *   1. Find the Supabase project URL in the page HTML.
 *   2. Extract the anon/publishable key from inline scripts or VITE_ bundle vars.
 *   3. Call the Supabase REST API with only that key to enumerate table names.
 *   4. Query each discovered table — if rows come back, RLS is disabled.
 *
 * Context: 83% of Supabase exposures involve RLS misconfiguration (Escape.tech, Feb 2026).
 * CVE-2025-48757 (Lovable breach) was caused by exactly this pattern — ~10% of all
 * Lovable-hosted apps had fully open tables leaking plaintext credentials.
 */
export async function checkSupabaseRLS(html: string): Promise<ScanVulnerability[]> {
  // 1. Find Supabase project URL
  const projectMatch = /https:\/\/([a-z0-9]{20})\.supabase\.co/.exec(html);
  if (!projectMatch) return [];

  const projectRef = projectMatch[1];
  const supabaseOrigin = `https://${projectRef}.supabase.co`;
  const restBase = `${supabaseOrigin}/rest/v1/`;

  // 2. Extract anon/publishable key from HTML / inline bundle
  let anonKey: string | null = null;

  // New format: sb_publishable_...
  const newFmtMatch = /\bsb_publishable_[a-zA-Z0-9_-]{20,}\b/.exec(html);
  if (newFmtMatch) {
    anonKey = newFmtMatch[0];
  } else {
    // Old format: JWT in a Supabase-init context
    const jwtMatch = /(?:supabaseKey|anon(?:Key|_key)|ANON_KEY|SUPABASE_ANON_KEY|apikey)\s*[:=,\s]+["'`]?(eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,})/.exec(html);
    if (jwtMatch) anonKey = jwtMatch[1] ?? null;
  }

  // 2b. If no key found in context, look for any bare JWT next to supabase
  if (!anonKey) {
    const bareJwt = /eyJ[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/.exec(html);
    if (bareJwt) anonKey = bareJwt[0];
  }

  if (!anonKey) {
    // Supabase detected but key is in a lazy-loaded bundle — advise manual check
    // Nothing was observed here — no key, no request — so this is a pointer to
    // check, not a finding about the customer's database: INFO, low confidence.
    return [vuln({
      name: "Supabase Detected — Verify Row Level Security (RLS)",
      severity: "info",
      category: "Database Security",
      description: "A Supabase backend was detected, but its public key could not be read from the page, so no table was tested. Nothing here shows a misconfiguration. Row Level Security (RLS) is the access control for Supabase data (CVE-2025-48757 affected apps that left it off), so it is worth confirming it is enabled on every table that holds non-public data.",
      evidence: `Supabase project detected: ${supabaseOrigin}\nAnon key could not be extracted from inline HTML — it may be in a JS bundle. No request was made to the project.`,
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
  if (!schemaRes || schemaRes.status !== 200) return [];

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
            // Rows from a public catalogue (products, posts...) are not RLS-off.
            (classifyExposure(table, rows) === "public" ? publicTables : exposedTables).push(table);
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
  if (publicTables.length > 0) {
    return [vuln({
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
    })];
  }

  return [];
}

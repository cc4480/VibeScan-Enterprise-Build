import { probeTables, enumerateSupabaseTables, extractTableNamesFromContent, extractStorageBucketNames, testStorageBuckets } from "./supabase-probes-tables";
import { reportServiceRoleKey, reportTableFindings } from "./supabase-probes-report";
import { probeSupabaseAuth, probeSupabaseStorageContents } from "./baasDepth";
import type { ScanVulnerability } from "./scanner";
import { MAX_TABLES_TO_TEST, vuln } from "./supabase-probes-core";
import { extractSupabaseConfig } from "./supabase-probes-config";

/**
 * Supabase security probes for vibeStackProbes.ts.
 * Detects exposed Supabase backends, missing RLS policies, and service_role key exposure.
 * Extracted from vibeStackProbes.ts to reduce its size.
 */








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
  reportServiceRoleKey(content, findings);

  // ── Supabase API probes ───────────────────────────────────────────────────
  const config = extractSupabaseConfig(content);
  if (!config) return;

  const { projectRef, anonKey, baseUrl } = config;

  await probeSupabaseAuth(baseUrl, anonKey, findings);
  await probeSupabaseStorageContents(baseUrl, anonKey, findings, extractStorageBucketNames(content));

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


  const results = await probeTables(baseUrl, anonKey, tables);
  reportTableFindings({ ...results, tables, projectRef, baseUrl }, findings);

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

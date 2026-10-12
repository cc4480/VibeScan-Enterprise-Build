/**
 * Supabase migration review: tables created without Row Level Security, and policies that open a table to everyone.
 *
 * CVE-2025-48757 (10.3% of the Lovable apps analysed) was tables with RLS off. The live scan can only find that once
 * the app is deployed and its URL and key are readable; the migrations that create the tables are in the repository
 * before that, and after the app is changed. This reads them. It is a static read of SQL, so it states what the files
 * say, not what the database holds: RLS can also be switched on in the dashboard, which no migration records.
 *
 * Statements are applied in file-name order (Supabase runs migrations by timestamp), so a later `enable row level
 * security` or `drop table` settles an earlier create. Only tables in the public schema are judged: that is the
 * schema the REST API exposes.
 */
import { classifyExposure } from "./baasExposure";
import { repoFinding, type RepoFile, type RepoRef } from "./repoFinding";
import type { ScanVulnerability } from "./scanner";

const MIGRATION_PATH = /(?:^|\/)supabase\/(?:migrations\/[\w.-]+\.sql|schema\.sql)$/i;
export const isMigrationPath = (p: string) => MIGRATION_PATH.test(p);

/** Comments out, so a commented-out statement is not read as one. */
function stripSqlComments(sql: string): string {
  return sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ");
}

const IDENT = String.raw`(?:"([\w$]+)"|([\w$]+))`;
const QUALIFIED = String.raw`(?:(?:"?(\w+)"?)\.)?` + IDENT;

interface TableState { createdIn: string; rls: boolean }

function parseName(m: RegExpExecArray, schemaIdx: number): { schema: string; name: string } {
  return { schema: (m[schemaIdx] ?? "public").toLowerCase(), name: (m[schemaIdx + 1] ?? m[schemaIdx + 2] ?? "").toLowerCase() };
}

/** The table's final state after all migrations, in order. */
export function tableStates(files: RepoFile[]): Map<string, TableState> {
  const tables = new Map<string, TableState>();
  const ordered = files.filter((f) => isMigrationPath(f.path)).sort((a, b) => a.path.localeCompare(b.path));
  for (const f of ordered) {
    const sql = stripSqlComments(f.content);
    // Statement by statement, in the order they appear.
    for (const stmt of sql.split(";")) {
      let m = new RegExp(String.raw`^\s*create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?` + QUALIFIED, "i").exec(stmt);
      if (m) {
        const { schema, name } = parseName(m, 1);
        if (schema === "public" && name) tables.set(name, { createdIn: f.path, rls: tables.get(name)?.rls ?? false });
        continue;
      }
      m = new RegExp(String.raw`^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?` + QUALIFIED + String.raw`\s+(enable|disable|force)\s+row\s+level\s+security`, "i").exec(stmt);
      if (m) {
        const { schema, name } = parseName(m, 1);
        const t = tables.get(name);
        if (schema === "public" && t) t.rls = m[4]!.toLowerCase() !== "disable";
        continue;
      }
      m = new RegExp(String.raw`^\s*drop\s+table\s+(?:if\s+exists\s+)?` + QUALIFIED, "i").exec(stmt);
      if (m) {
        const { schema, name } = parseName(m, 1);
        if (schema === "public") tables.delete(name);
      }
    }
  }
  return tables;
}

interface Policy { table: string; command: string; roles: string[]; open: boolean; file: string; name: string }

/** `create policy "n" on t for select to anon using (true)` and the like. */
export function policies(files: RepoFile[]): Policy[] {
  const out: Policy[] = [];
  for (const f of files.filter((x) => isMigrationPath(x.path))) {
    for (const stmt of stripSqlComments(f.content).split(";")) {
      const m = new RegExp(String.raw`^\s*create\s+policy\s+(?:"([^"]+)"|(\w+))\s+on\s+` + QUALIFIED + String.raw`([\s\S]*)$`, "i").exec(stmt);
      if (!m) continue;
      const schema = (m[3] ?? "public").toLowerCase();
      const table = (m[4] ?? m[5] ?? "").toLowerCase();
      if (schema !== "public" || !table) continue;
      const rest = m[6] ?? "";
      const command = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest)?.[1]?.toLowerCase() ?? "all";
      const to = /\bto\s+([\w",\s]+?)(?=\s+(?:using|with)\b|$)/i.exec(rest)?.[1];
      // No TO clause means every role, anon included.
      const roles = to ? to.split(",").map((r) => r.replace(/"/g, "").trim().toLowerCase()).filter(Boolean) : ["public"];
      const open = /\busing\s*\(\s*true\s*\)/i.test(rest) || /\bwith\s+check\s*\(\s*true\s*\)/i.test(rest);
      out.push({ table, command, roles, open, file: f.path, name: m[1] ?? m[2] ?? "" });
    }
  }
  return out;
}

export function supabaseMigrationFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const migrations = files.filter((f) => isMigrationPath(f.path));
  if (migrations.length === 0) return [];
  const findings: ScanVulnerability[] = [];

  // 1. Tables created, and never given RLS, in any migration.
  const unprotected = [...tableStates(files).entries()].filter(([, s]) => !s.rls);
  if (unprotected.length > 0) {
    const names = unprotected.map(([n]) => n);
    findings.push(repoFinding({
      ref, path: unprotected[0]![1].createdIn,
      name: "Supabase Tables Created Without Row Level Security",
      severity: "high", category: "Broken Access Control", cweId: "CWE-862", cvssScore: 8.1, confidence: 75, wstgId: "WSTG-ATHZ-01",
      description:
        `${names.length} table(s) in the public schema are created by the migrations and never have Row Level Security enabled: ${names.slice(0, 12).join(", ")}. ` +
        "Supabase exposes every public table through its REST API, so once the app is deployed anyone holding the public anon key can read (and, unless a grant prevents it, write) every row. " +
        "This is the pattern behind CVE-2025-48757, which affected about 10% of the Lovable-built apps analysed.",
      detail: `Tables without RLS: ${names.join(", ")}\nCreated in: ${[...new Set(unprotected.map(([, s]) => s.createdIn))].slice(0, 5).join(", ")}\n(RLS can also be switched on in the Supabase dashboard, which no migration records; check there before treating this as confirmed.)`,
      solution:
        "Add to a new migration, for each table: ALTER TABLE public.<table> ENABLE ROW LEVEL SECURITY; then add policies scoped to the caller, for example CREATE POLICY own_rows ON public.<table> FOR SELECT TO authenticated USING ((select auth.uid()) = user_id); " +
        "Enabling RLS without a policy blocks all access, so add the policies in the same migration.",
    }));
  }

  // 2. Policies that open a table.
  const states = tableStates(files);
  for (const p of policies(files)) {
    if (!p.open || !states.has(p.table)) continue;
    const toAnon = p.roles.some((r) => r === "anon" || r === "public");
    const toSignedIn = p.roles.includes("authenticated");
    const writes = p.command !== "select";
    const kind = classifyExposure(p.table, []);
    if (toAnon && writes) {
      findings.push(repoFinding({
        ref, path: p.file,
        name: `Supabase Policy Lets Anyone ${p.command === "all" ? "Read and Write" : p.command[0]!.toUpperCase() + p.command.slice(1)} "${p.table}"`,
        severity: "high", category: "Broken Access Control", cweId: "CWE-862", cvssScore: 8.1, confidence: 80, wstgId: "WSTG-ATHZ-01",
        description: `The policy "${p.name}" on public.${p.table} applies to ${p.roles.join(", ")} (which includes the public anon key), allows ${p.command.toUpperCase()}, and its condition is simply true. Anyone with the anon key can ${p.command === "all" ? "read, insert, change and delete" : p.command} rows.`,
        detail: `Policy: ${p.name}\nTable: public.${p.table}\nFor: ${p.command}  To: ${p.roles.join(", ")}  Condition: true`,
        solution: "Scope the policy to the caller: TO authenticated USING ((select auth.uid()) = user_id), and use WITH CHECK for inserts and updates. Keep anon read access only on tables that are public by design.",
      }));
    } else if (toAnon && kind !== "public") {
      findings.push(repoFinding({
        ref, path: p.file,
        name: `Supabase Policy Lets Anyone Read "${p.table}"`,
        severity: kind === "sensitive" ? "high" : "info", category: "Broken Access Control", cweId: "CWE-862", cvssScore: kind === "sensitive" ? 7.5 : 0, confidence: kind === "sensitive" ? 75 : 40, wstgId: "WSTG-ATHZ-01",
        description: `The policy "${p.name}" on public.${p.table} lets ${p.roles.join(", ")} (including the public anon key) SELECT with a condition that is simply true, so every row is readable by anyone. ${kind === "sensitive" ? "The table's name suggests personal or private data." : "If the table holds public content (announcements, products) this is intended; if it holds anything per-user it is not."}`,
        detail: `Policy: ${p.name}\nTable: public.${p.table}\nFor: select  To: ${p.roles.join(", ")}  Condition: true`,
        solution: "If the rows are not meant for everyone, replace the condition: USING ((select auth.uid()) = user_id), or USING (published = true) for published content.",
      }));
    } else if (toSignedIn && kind !== "public") {
      findings.push(repoFinding({
        ref, path: p.file,
        name: `Supabase Policy Lets Every Signed-In User Reach All Rows of "${p.table}"`,
        severity: "medium", category: "Broken Access Control", cweId: "CWE-639", cvssScore: 6.5, confidence: 55, wstgId: "WSTG-ATHZ-04",
        description: `The policy "${p.name}" on public.${p.table} allows ${p.command.toUpperCase()} to any authenticated user with a condition that is simply true. Anyone who can sign up can reach every user's rows. This is the permissive-policy pattern in which signing in is treated as authorisation.`,
        detail: `Policy: ${p.name}\nTable: public.${p.table}\nFor: ${p.command}  To: authenticated  Condition: true`,
        solution: "Compare the row's owner with the caller: USING ((select auth.uid()) = user_id). Use true only for data every signed-in user is meant to share.",
      }));
    }
  }
  return findings;
}

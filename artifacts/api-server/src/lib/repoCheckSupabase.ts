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

interface Policy { table: string; command: string; roles: string[]; open: boolean; intended: boolean; file: string; name: string }

/** A policy whose comment says it exists for tests or a demo ("for backward compatibility with old tests"). Read from the raw text, since comments are stripped before parsing. */
const intendedForTests = (raw: string, name: string): boolean => {
  const at = name ? raw.search(new RegExp(String.raw`create\s+policy\s+"?${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"?`, "i")) : -1;
  return at >= 0 && /\b(?:tests?|testing|examples?|demos?|fixtures?|playground)\b/i.test(raw.slice(Math.max(0, at - 300), at));
};

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
      const name = m[1] ?? m[2] ?? "";
      out.push({ table, command, roles, open, intended: intendedForTests(f.content, name), file: f.path, name });
    }
  }
  return out;
}


/** Everything after `create function ... (` up to the end of the statement, with the dollar-quoted body in the middle left out. */
function functionAttributes(after: string): string {
  const open = /\$(\w*)\$/.exec(after);
  if (!open) return after.split(";")[0] ?? "";
  const tag = open[0];
  const close = after.indexOf(tag, open.index + tag.length);
  if (close < 0) return after.slice(0, open.index);
  return `${after.slice(0, open.index)} ${(after.slice(close + tag.length).split(";")[0] ?? "")}`;
}

/** SECURITY DEFINER functions in the public schema whose definition does not pin `search_path` (Supabase database linter 0011). */
export function definerFunctionsWithoutSearchPath(files: RepoFile[]): Array<{ name: string; file: string }> {
  const out: Array<{ name: string; file: string }> = [];
  for (const f of files.filter((x) => isMigrationPath(x.path))) {
    const sql = stripSqlComments(f.content);
    for (const m of sql.matchAll(/create\s+(?:or\s+replace\s+)?function\s+(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?\s*\(/gi)) {
      if ((m[1] ?? "public").toLowerCase() !== "public") continue;
      const attrs = functionAttributes(sql.slice(m.index! + m[0].length));
      if (/security\s+definer/i.test(attrs) && !/set\s+search_path/i.test(attrs)) out.push({ name: m[2]!, file: f.path });
    }
  }
  return out;
}

/** Views in the public schema created without `security_invoker`, so they run with their owner's rights and skip RLS (linter 0010). */
export function viewsWithoutInvoker(files: RepoFile[], states: Map<string, TableState>): Array<{ name: string; file: string; readsRlsTable: boolean }> {
  const out: Array<{ name: string; file: string; readsRlsTable: boolean }> = [];
  const ordered = files.filter((f) => isMigrationPath(f.path)).sort((a, b) => a.path.localeCompare(b.path));
  for (const f of ordered) {
    for (const stmt of stripSqlComments(f.content).split(";")) {
      const m = /^\s*create\s+(?:or\s+replace\s+)?view\s+(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?\s*(?:\([^)]*\)\s*)?(?:with\s*\(([^)]*)\)\s*)?as\s+([\s\S]*)$/i.exec(stmt);
      if (!m || (m[1] ?? "public").toLowerCase() !== "public") continue;
      if (/security_invoker\s*(?:=\s*)?(?:true|on|1)\b/i.test(m[3] ?? "")) continue;
      const reads = [...m[4]!.matchAll(/\b(?:from|join)\s+(?:"?public"?\s*\.\s*)?"?(\w+)"?/gi)].map((r) => r[1]!.toLowerCase());
      out.push({ name: m[2]!, file: f.path, readsRlsTable: reads.some((t) => states.get(t)?.rls === true) });
    }
  }
  return out;
}

/** `create policy ... on storage.objects` that lets the anon role (or everyone) list and read a bucket with no check of the owner. */
export function openStoragePolicies(files: RepoFile[]): Array<{ policy: string; bucket: string | null; file: string }> {
  const out: Array<{ policy: string; bucket: string | null; file: string }> = [];
  for (const f of files.filter((x) => isMigrationPath(x.path))) {
    for (const stmt of stripSqlComments(f.content).split(";")) {
      const m = /^\s*create\s+policy\s+(?:"([^"]+)"|(\w+))\s+on\s+"?storage"?\s*\.\s*"?objects"?([\s\S]*)$/i.exec(stmt);
      if (!m) continue;
      const rest = m[3] ?? "";
      const command = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest)?.[1]?.toLowerCase() ?? "all";
      if (command !== "select" && command !== "all") continue;
      const to = /\bto\s+([\w",\s]+?)(?=\s+(?:using|with)\b|$)/i.exec(rest)?.[1];
      const roles = to ? to.split(",").map((r) => r.replace(/"/g, "").trim().toLowerCase()).filter(Boolean) : ["public"];
      if (!roles.some((r) => r === "anon" || r === "public")) continue;
      if (/auth\s*\.\s*(?:uid|jwt)\s*\(|\bowner(?:_id)?\b/i.test(rest)) continue;
      out.push({ policy: m[1] ?? m[2] ?? "", bucket: /bucket_id\s*=\s*'([^']+)'/i.exec(rest)?.[1] ?? null, file: f.path });
    }
  }
  return out;
}

function databaseHygieneFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const definers = definerFunctionsWithoutSearchPath(files);
  if (definers.length > 0) {
    out.push(repoFinding({
      ref, path: definers[0]!.file,
      name: "Supabase Function Runs With Its Owner's Rights and No Pinned search_path",
      severity: "low", category: "Broken Access Control", cweId: "CWE-250", cvssScore: 3.7, confidence: 60, wstgId: "WSTG-ATHZ-02",
      description: `${definers.length} SECURITY DEFINER function(s) in the public schema do not set search_path: ${definers.map((d) => d.name).join(", ")}. They run with their owner's privileges, and without a pinned search_path a caller who can create objects in a schema earlier on the path can make the function call their object instead. This is Supabase database linter rule 0011.`,
      detail: `Functions: ${definers.map((d) => d.name).join(", ")}\nIn: ${[...new Set(definers.map((d) => d.file))].slice(0, 4).join(", ")}`,
      solution: "Add SET search_path = '' to the function and schema-qualify every object it uses (public.profiles, not profiles). Use SECURITY INVOKER where owner rights are not needed.",
    }));
  }
  const views = viewsWithoutInvoker(files, tableStates(files));
  if (views.length > 0) {
    const reachesRls = views.some((v) => v.readsRlsTable);
    out.push(repoFinding({
      ref, path: views[0]!.file,
      name: "Supabase View Bypasses Row Level Security (no security_invoker)",
      severity: reachesRls ? "medium" : "low", category: "Broken Access Control", cweId: "CWE-862", cvssScore: reachesRls ? 6.5 : 3.1, confidence: reachesRls ? 60 : 40, wstgId: "WSTG-ATHZ-01",
      description: `${views.length} view(s) in the public schema are created without security_invoker: ${views.map((v) => v.name).join(", ")}. A view runs with its owner's rights, so it returns every row of the tables it reads whatever the caller's RLS policies say, and the Supabase API exposes public views like tables. ${reachesRls ? "At least one reads a table that has RLS on, so the view opens it up." : "The tables they read have no RLS in these migrations, so here the view adds no new exposure."} This is Supabase database linter rule 0010.`,
      detail: `Views: ${views.map((v) => v.name).join(", ")}\nIn: ${[...new Set(views.map((v) => v.file))].slice(0, 4).join(", ")}`,
      solution: "Create the view WITH (security_invoker = true) (Postgres 15 and later), or revoke access from anon and authenticated and expose the data through a function.",
    }));
  }
  const storage = openStoragePolicies(files);
  if (storage.length > 0) {
    const buckets = [...new Set(storage.map((s) => s.bucket).filter((b): b is string => !!b))];
    out.push(repoFinding({
      ref, path: storage[0]!.file,
      name: `Supabase Storage Policy Lets Anyone List and Read ${buckets.length ? `Bucket "${buckets.join('", "')}"` : "Storage Objects"}`,
      severity: "medium", category: "Broken Access Control", cweId: "CWE-200", cvssScore: 5.3, confidence: 55, wstgId: "WSTG-ATHZ-01",
      description: `The policy "${storage[0]!.policy}" on storage.objects lets the anon role (or everyone) SELECT${buckets.length ? ` objects in ${buckets.join(", ")}` : ""} with no check of who owns the file. A SELECT policy is what lets a client list a bucket's contents, not only fetch a file whose name it already knows, so anyone with the public key can enumerate every file name and read each file.`,
      detail: `Policy: ${storage[0]!.policy}${buckets.length ? `\nBucket: ${buckets.join(", ")}` : ""}\nIn: ${[...new Set(storage.map((s) => s.file))].slice(0, 4).join(", ")}`,
      solution: "If the files are public assets, a public bucket serves them by URL without any SELECT policy: remove the policy. If they are per-user, scope it: TO authenticated USING (bucket_id = 'x' AND (storage.foldername(name))[1] = (select auth.uid())::text).",
    }));
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
    // A policy its own comment says is for tests (the demo app's todos table) is shown as information, once, not as a live hole.
    if (p.intended) {
      findings.push(repoFinding({
        ref, path: p.file,
        name: `Supabase Policy Opens "${p.table}" (for a test or demo)`,
        severity: "info", category: "Broken Access Control", cweId: "CWE-862", cvssScore: 0, confidence: 40, wstgId: "WSTG-ATHZ-01",
        description: `The policy "${p.name}" on public.${p.table} is open (its condition is simply true), and its comment says it exists for tests or a demo. It is shown as information so that it is not mistaken for a production table.`,
        detail: `Policy: ${p.name}\nTable: public.${p.table}\nFor: ${p.command}  To: ${p.roles.join(", ")}  Condition: true`,
        solution: "If this migration ever reaches a production database, remove the policy. Otherwise no action is needed.",
      }));
      continue;
    }
    const toAnon = p.roles.some((r) => r === "anon" || r === "public");
    const toSignedIn = p.roles.includes("authenticated");
    const writes = p.command !== "select";
    const kind = classifyExposure(p.table, []);
    if (toAnon && p.command === "insert") {
      // An open insert with no way to read rows back is how a contact or waitlist form works. It is still unauthenticated
      // write access (spam, storage abuse), so it is reported, but low whatever the table is called: what the table's
      // name says about its contents matters for reading rows, and this policy opens none.
      findings.push(repoFinding({
        ref, path: p.file,
        name: `Supabase Policy Lets Anyone Insert "${p.table}"`,
        severity: "low", category: "Broken Access Control", cweId: "CWE-862", cvssScore: 3.1, confidence: 50, wstgId: "WSTG-ATHZ-01",
        description: `The policy "${p.name}" on public.${p.table} lets ${p.roles.join(", ")} (including the public anon key) INSERT rows with a condition that is simply true. That is the usual setup for a public form, and it means anyone can add rows without signing in: add rate limiting or a CAPTCHA, and keep SELECT closed (this policy does not open it).`,
        detail: `Policy: ${p.name}\nTable: public.${p.table}\nFor: insert  To: ${p.roles.join(", ")}  Condition: true`,
        solution: "If the table should only take rows from signed-in users, change the role to authenticated and check the owner: WITH CHECK ((select auth.uid()) = user_id). For a public form, keep it and put a rate limit or CAPTCHA in front.",
      }));
    } else if (toAnon && writes) {
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
  findings.push(...databaseHygieneFindings(files, ref));
  return findings;
}

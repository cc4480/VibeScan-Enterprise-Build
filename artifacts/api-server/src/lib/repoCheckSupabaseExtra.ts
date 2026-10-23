/**
 * Supabase checks beyond "RLS is on" (repoCheckSupabase.ts), taken from the gaps that Supabase's own database linter and
 * the vibe-code scanners report most often in AI-built apps:
 *
 *   - a policy or function that decides access from `user_metadata`, which every user can edit about themselves;
 *   - a SECURITY DEFINER function that anyone with the public key can call through /rest/v1/rpc;
 *   - anonymous sign-ins, which make every "TO authenticated" policy apply to anonymous visitors;
 *   - sensitive-looking columns in tables the API exposes;
 *   - a public storage bucket named like private documents.
 *
 * Static SQL, so each finding says what the files say and is as confident as the text allows.
 */
import { isMigrationPath } from "./repoCheckSupabase";
import { repoFinding, type RepoFile, type RepoRef } from "./repoFinding";
import type { ScanVulnerability } from "./scanner";

const stripComments = (sql: string) => sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ");
const migrations = (files: RepoFile[]) => files.filter((f) => isMigrationPath(f.path)).sort((a, b) => a.path.localeCompare(b.path));

/** Statements, kept with the file they came from. A dollar-quoted body may hold semicolons, so those are protected. */
function statements(f: RepoFile): string[] {
  const protectedBodies = stripComments(f.content).replace(/\$(\w*)\$[\s\S]*?\$\1\$/g, (m) => m.replace(/;/g, "\u0000"));
  return protectedBodies.split(";").map((s) => s.replace(/\u0000/g, ";"));
}

const USER_META = /\buser_metadata\b|\braw_user_meta_data\b/i;

function userMetadataFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const hits: Array<{ kind: string; name: string; file: string }> = [];
  for (const f of migrations(files)) {
    for (const stmt of statements(f)) {
      const p = /^\s*create\s+policy\s+(?:"([^"]+)"|(\w+))\s+on\s/i.exec(stmt);
      if (p && USER_META.test(stmt)) { hits.push({ kind: "policy", name: p[1] ?? p[2]!, file: f.path }); continue; }
      const fn = /^\s*create\s+(?:or\s+replace\s+)?function\s+(?:"?\w+"?\s*\.\s*)?"?(\w+)"?\s*\(/i.exec(stmt);
      // A trigger that copies the sign-up name or avatar out of the metadata (Supabase's own handle_new_user) decides
      // nothing. A function is an access decision when it compares the metadata with a role or permission.
      if (fn && USER_META.test(stmt) && !/returns\s+trigger/i.test(stmt) &&
          /(?:user_metadata|raw_user_meta_data)[^;]{0,80}\b(?:role|admin|permission|tenant|org\w*|plan|access|is_\w+)\b/i.test(stmt)) {
        hits.push({ kind: "function", name: fn[1]!, file: f.path });
      }
    }
  }
  if (hits.length === 0) return [];
  return [repoFinding({
    ref, path: hits[0]!.file, name: "Supabase Access Decided From user_metadata",
    severity: "high", category: "Broken Access Control", cweId: "CWE-639", cvssScore: 8.1, confidence: 80, wstgId: "WSTG-ATHZ-02",
    description: `${hits.length === 1 ? "A" : `${hits.length}`} ${hits[0]!.kind}${hits.length === 1 ? "" : "s"} read user_metadata to decide who may do what: ${hits.slice(0, 5).map((h) => `${h.kind} ${h.name}`).join(", ")}. Every signed-in user can change their own user_metadata with supabase.auth.updateUser, so anyone can give themselves the role the policy is looking for. This is Supabase database linter rule 0015.`,
    detail: hits.slice(0, 6).map((h) => `${h.kind}: ${h.name} (${h.file})`).join("\n"),
    solution: "Keep roles in app_metadata (only the server and service role can write it), or in a table users cannot write to, and read that in the policy. Treat every role already stored in user_metadata as forgeable.",
  })];
}

/** Public-schema SECURITY DEFINER functions that return a value, with no check of the caller in their body and no REVOKE. */
function definerRpcFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const defined = new Map<string, string>();
  const revoked = new Set<string>();
  let blanketRevoke = false;
  for (const f of migrations(files)) {
    for (const stmt of statements(f)) {
      const fn = /^\s*create\s+(?:or\s+replace\s+)?function\s+(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?\s*\(/i.exec(stmt);
      if (fn && (fn[1] ?? "public").toLowerCase() === "public") {
        if (!/security\s+definer/i.test(stmt) || /returns\s+trigger/i.test(stmt)) continue;
        // A function that looks up the caller before it acts is its own gate.
        if (/\bauth\s*\.\s*(?:uid|jwt|role)\s*\(|current_setting\s*\(\s*'request\.jwt/i.test(stmt)) continue;
        defined.set(fn[2]!.toLowerCase(), f.path);
        continue;
      }
      const rv = /^\s*revoke\s+(?:execute|all)\b[^;]*?\bon\s+function\s+(?:"?public"?\s*\.\s*)?"?(\w+)"?[^;]*?\bfrom\b[^;]*\b(?:public|anon)\b/i.exec(stmt);
      if (rv) revoked.add(rv[1]!.toLowerCase());
      if (/^\s*(?:alter\s+default\s+privileges[\s\S]*revoke\s+execute|revoke\s+(?:execute|all)\s+on\s+all\s+functions)/i.test(stmt)) blanketRevoke = true;
    }
  }
  if (blanketRevoke) return [];
  const exposed = [...defined].filter(([name]) => !revoked.has(name));
  if (exposed.length === 0) return [];
  return [repoFinding({
    ref, path: exposed[0]![1], name: "Supabase SECURITY DEFINER Function Callable by Anyone",
    severity: "medium", category: "Broken Access Control", cweId: "CWE-284", cvssScore: 6.5, confidence: 50, wstgId: "WSTG-ATHZ-02",
    description: `${exposed.length} SECURITY DEFINER function(s) in the public schema can be called by the public key through /rest/v1/rpc, and none checks who the caller is or revokes EXECUTE from anon: ${exposed.slice(0, 5).map(([n]) => n).join(", ")}. A definer function runs with its owner's rights, so it bypasses RLS: whatever it reads or changes, any visitor can trigger. This is Supabase database linter rules 0028 and 0029. The scanner reads SQL only, so check what each function does and whether a later migration or the dashboard revokes it.`,
    detail: exposed.slice(0, 6).map(([n, file]) => `function: ${n} (${file})`).join("\n"),
    solution: "REVOKE EXECUTE ON FUNCTION name FROM public, anon (and from authenticated if signed-in users should not call it), or use SECURITY INVOKER, or check auth.uid() at the top of the function and raise if it is null.",
  })];
}

const SENSITIVE_COLUMN = /^(?:password|passwd|pwd|ssn|social_security(?:_number)?|credit_card(?:_number)?|card_number|cvv|cvc|secret|api_key|private_key|access_token|refresh_token)$/i;

function sensitiveColumnFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const hits: string[] = [];
  let first = "";
  for (const f of migrations(files)) {
    for (const stmt of statements(f)) {
      const t = /^\s*create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?\s*\(([\s\S]*)\)\s*$/i.exec(stmt);
      if (!t || (t[1] ?? "public").toLowerCase() !== "public") continue;
      for (const line of t[3]!.split(/,\s*\n|\n\s*,/)) {
        const col = /^\s*"?(\w+)"?\s+\w/.exec(line)?.[1];
        if (col && SENSITIVE_COLUMN.test(col)) { hits.push(`${t[2]}.${col}`); first ||= f.path; }
      }
    }
  }
  if (hits.length === 0) return [];
  return [repoFinding({
    ref, path: first, name: "Supabase Table Holds a Sensitive-Looking Column",
    severity: "medium", category: "Sensitive Data Exposure", cweId: "CWE-312", cvssScore: 5.3, confidence: 45, wstgId: "WSTG-ATHZ-01",
    description: `Tables in the public schema (which the API exposes) have columns that look like secrets or personal data: ${hits.slice(0, 6).join(", ")}. A column cannot be hidden by RLS on its own: any policy that lets a user read the row lets them read every column in it. Linter rule 0023.`,
    detail: `Columns: ${hits.slice(0, 8).join(", ")}`,
    solution: "Do not store passwords or card numbers at all (use Supabase Auth and a payment provider). For other sensitive values, move them to a table with its own strict policy or to a private schema, and revoke column privileges from anon and authenticated.",
  })];
}

const SENSITIVE_BUCKET = /invoice|document|private|receipt|contract|passport|id[-_]?card|licen[sc]e|statement|backup|export|resume|\bcv\b|medical|kyc|payroll|tax/i;

function publicBucketFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const hits: string[] = [];
  let first = "";
  for (const f of migrations(files)) {
    for (const stmt of statements(f)) {
      const ins = /^\s*insert\s+into\s+"?storage"?\s*\.\s*"?buckets"?\s*\(([^)]*)\)\s*values\s*\(\s*'([^']+)'([^)]*)\)/i.exec(stmt);
      if (ins) {
        const cols = ins[1]!.split(",").map((c) => c.trim().replace(/"/g, "").toLowerCase());
        const values = `'${ins[2]}'${ins[3]}`.split(",").map((v) => v.trim().toLowerCase());
        const isPublic = values[cols.indexOf("public")] === "true";
        if (cols.includes("public") && isPublic && SENSITIVE_BUCKET.test(ins[2]!)) { hits.push(ins[2]!); first ||= f.path; }
        continue;
      }
      const upd = /^\s*update\s+"?storage"?\s*\.\s*"?buckets"?\s+set\s+public\s*=\s*true\b[\s\S]*?\bid\s*=\s*'([^']+)'/i.exec(stmt);
      if (upd && SENSITIVE_BUCKET.test(upd[1]!)) { hits.push(upd[1]!); first ||= f.path; }
    }
  }
  if (hits.length === 0) return [];
  return [repoFinding({
    ref, path: first, name: "Supabase Storage Bucket Named Like Private Files Is Public",
    severity: "medium", category: "Broken Access Control", cweId: "CWE-200", cvssScore: 5.3, confidence: 55, wstgId: "WSTG-ATHZ-01",
    description: `A storage bucket is created public although its name suggests private files: ${[...new Set(hits)].slice(0, 5).join(", ")}. A public bucket serves every object to anyone who has its URL, with no policy involved, and URLs leak through logs, referrers and shared links.`,
    detail: `Bucket: ${[...new Set(hits)].slice(0, 5).join(", ")}`,
    solution: "Make the bucket private and serve files through short-lived signed URLs (createSignedUrl) after checking the caller owns the file. Keep public buckets for assets that are meant to be public.",
  })];
}

/** supabase/config.toml: anonymous sign-ins and unconfirmed email sign-ups. */
export function supabaseAuthConfigFindings(f: RepoFile, ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const text = f.content.replace(/#[^\n]*/g, "");
  if (/^\s*enable_anonymous_sign_ins\s*=\s*true\b/im.test(text)) {
    out.push(repoFinding({
      ref, path: f.path, name: "Supabase Anonymous Sign-Ins Are Enabled",
      severity: "medium", category: "Broken Access Control", cweId: "CWE-284", cvssScore: 5.3, confidence: 60, wstgId: "WSTG-ATHZ-02",
      description: "Anonymous sign-ins are on. An anonymous visitor gets a real session whose role is `authenticated`, so every policy written `TO authenticated` (or checking auth.uid() is not null) applies to anyone who opens the site, not only to people who signed up. Check each policy, and read the `is_anonymous` claim where it matters.",
      solution: "Turn it off unless the app needs guest sessions. If it does, add `(auth.jwt() ->> 'is_anonymous')::boolean is not true` to the policies that should be for registered users only, and enable CAPTCHA protection.",
    }));
  }
  if (/\[auth\.email\][^[]*?^\s*enable_confirmations\s*=\s*false\b/ims.test(text)) {
    out.push(repoFinding({
      ref, path: f.path, name: "Supabase Email Sign-Ups Are Not Confirmed",
      severity: "low", category: "Authentication", cweId: "CWE-287", cvssScore: 3.7, confidence: 50, wstgId: "WSTG-ATHN-02",
      description: "Email confirmation is off, so anyone can create an account with an address they do not own, and an account can be registered in someone else's name before they arrive. This is the local config; the hosted project's setting is in the dashboard.",
      solution: "Set enable_confirmations = true for production, and use a separate local config if development needs it off.",
    }));
  }
  return out;
}

export function supabaseExtraFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  if (migrations(files).length === 0) return [];
  return [...userMetadataFindings(files, ref), ...definerRpcFindings(files, ref), ...sensitiveColumnFindings(files, ref), ...publicBucketFindings(files, ref)];
}

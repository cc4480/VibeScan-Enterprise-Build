import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { startOsvStub } from "./osvStub.testkit";
import { osvCache } from "./cveCheckOsv";

// OSV is the only network the dependency check uses. It is a real local server that answers like OSV.dev
// (lib/osvStub.testkit.ts), so the real client's queries, cache and error handling all run; the answers are decided here.
const osv = await startOsvStub();
beforeEach(() => osvCache.clear()); // a verdict cached by an earlier test would otherwise answer for this one
afterAll(() => osv.stop());

import { supabaseMigrationFindings } from "./repoCheckSupabase";
import { ciConfigFindings } from "./repoCheckCi";
import { scanRepository, chooseFiles } from "./repoScan";
import type { RepoSource } from "./repoSource";
import type { RepoFile, RepoRef } from "./repoFinding";

/**
 * The repository scan: Supabase migrations, CI and configuration, a few dangerous code patterns, dependencies, secrets.
 * Every rule has a clean twin: the same file done correctly, which must report nothing.
 */

const ref: RepoRef = { owner: "acme", repo: "taskflow" };
const f = (path: string, content: string): RepoFile => ({ path, content });
const names = (x: Array<{ name: string }>) => x.map((v) => v.name);

/** A repository held in memory. */
function memorySource(files: Record<string, string>, over: Partial<{ truncated: boolean; fail: Set<string>; status: "not_public_or_missing" }> = {}): RepoSource & { reads: string[] } {
  const reads: string[] = [];
  return {
    via: "public", reads,
    async open() {
      if (over.status) return { ok: false, status: over.status };
      return { ok: true, branch: "main", truncated: over.truncated ?? false, tree: Object.entries(files).map(([path, c]) => ({ path, size: c.length })) };
    },
    async read(path) { reads.push(path); return over.fail?.has(path) ? null : files[path] ?? null; },
  };
}

describe("scanRepository", () => {
  const vulnerable: Record<string, string> = {
    ".env.production": "VITE_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiJ9.abc123def456ghi\nSTRIPE_KEY=sk_live_Zk3pQ8vXw2LmN7rT9yBcD4fG\n",
    "supabase/migrations/001_init.sql": "create table public.profiles (id uuid);",
    ".github/workflows/pr.yml": "permissions: write-all\n",
    "src/server.ts": "eval(req.body.x)",
    "package.json": JSON.stringify({ dependencies: { lodash: "4.17.20" } }),
    "README.md": "# hi",
  };

  it("runs every check and says which files each one looked at", async () => {
    osv.vulnerable = new Set(["lodash@4.17.20"]);
    const out = await scanRepository(memorySource(vulnerable), ref);
    expect(out.status).toBe("scanned");
    const got = names(out.findings);
    expect(got).toEqual(expect.arrayContaining([
      "Supabase Tables Created Without Row Level Security",
      "GitHub Actions Workflow Requests write-all Permissions",
      "eval or new Function on Request Data",
      "Secret Exposed Through a Client-Side Environment Prefix",
    ]));
    expect(got.some((n) => /Stripe/i.test(n) && /source repository/.test(n))).toBe(true);
    expect(out.findings.some((v) => /lodash/.test(`${v.name} ${v.evidence ?? ""} ${v.description}`))).toBe(true);
    expect(out.checks!.map((c) => c.name)).toEqual(["repository secrets", "Supabase migrations (RLS and policies)", "CI and configuration", "dangerous code patterns", "dependency vulnerabilities (OSV)"]);
    expect(out.coverage).toMatchObject({ treeFiles: 6, read: 6, failedReads: 0 });
    // Nothing was left out, so there is no partial-coverage note.
    expect(names(out.findings)).not.toContain("GitHub source scan covered only part of the repository");
    // A secret is never written out whole.
    expect(JSON.stringify(out.findings)).not.toContain("sk_live_Zk3pQ8vXw2LmN7rT9yBcD4fG");
  });

  it("clean twin: the same repository done correctly reports nothing, and says every check ran", async () => {
    osv.vulnerable = new Set();
    const clean = {
      ".env.example": "VITE_SUPABASE_URL=\nVITE_SUPABASE_PUBLISHABLE_KEY=\n",
      "supabase/migrations/001_init.sql": "create table public.profiles (id uuid, user_id uuid); alter table public.profiles enable row level security;\ncreate policy own on public.profiles for all to authenticated using ((select auth.uid()) = user_id);",
      ".github/workflows/ci.yml": "permissions:\n  contents: read\non: [pull_request]\n",
      "src/server.ts": "db.query('SELECT 1 WHERE id = $1', [req.params.id])",
      "package.json": JSON.stringify({ dependencies: { lodash: "4.17.21" } }),
    };
    const out = await scanRepository(memorySource(clean), ref);
    expect(out.findings).toEqual([]);
    expect(out.checks!.every((c) => c.files > 0)).toBe(true);
  });

  it("reads every text file, whatever its language, and checks each for secrets", async () => {
    const src = memorySource({
      "app/main.py": 'STRIPE = "sk_live_Zk3pQ8vXw2LmN7rT9yBcD4fG"\n',
      "docs/README.md": "# hello",
      "static/logo.png": "not text",
      "assets/font.woff2": "not text",
    });
    const out = await scanRepository(src, ref);
    expect([...src.reads].sort()).toEqual(["app/main.py", "docs/README.md"]);
    expect(out.coverage).toMatchObject({ treeFiles: 4, chosen: 2, read: 2 });
    expect(names(out.findings).some((n) => /Stripe/i.test(n) && /source repository/.test(n))).toBe(true);
  });

  it("shows a secret-shaped value in a test file as information, apart from the same kind of value in code that ships", async () => {
    const key = 'const k = "sk_live_Zk3pQ8vXw2LmN7rT9yBcD4fG";\n';
    const out = await scanRepository(memorySource({ "server/pay.test.ts": key, "docs/guide.md": key, "app/pay.py": key }), ref);
    const stripe = out.findings.filter((v) => /Stripe/i.test(v.name));
    const shipped = stripe.filter((v) => /in source repository/.test(v.name));
    const fake = stripe.filter((v) => /test or example file/.test(v.name));
    expect(shipped).toHaveLength(1);
    expect(shipped[0]!.severity).toBe("critical");
    expect(shipped[0]!.evidence).toContain("app/pay.py");
    // The two test-file hits are one finding, listing both files.
    expect(fake).toHaveLength(1);
    expect(fake[0]!.severity).toBe("info");
    expect(fake[0]!.evidence).toContain("server/pay.test.ts");
    expect(fake[0]!.evidence).toContain("docs/guide.md");
  });

  it("shows a value its own code calls forged, dummy or a probe as information, and a plain one as before", async () => {
    const out = await scanRepository(memorySource({
      "server/probe.ts": 'const FORGED = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcm9iZSJ9.c2lnbmF0dXJlLXByb2Jl";\n',
      "server/auth.ts": 'const session = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLWFkbWlu";\n',
    }), ref);
    const jwt = out.findings.filter((v) => /JWT/i.test(v.name));
    expect(jwt.find((v) => /deliberately fake/.test(v.name))?.severity).toBe("info");
    expect(jwt.find((v) => /in source repository/.test(v.name))?.severity).toBe("high");
  });

  it("counts the files it leaves alone on purpose, by reason, so the report can say why", async () => {
    const out = await scanRepository(memorySource({
      "src/a.ts": "export const a = 1;", "static/logo.png": "x", "static/hero.jpg": "x", "assets/font.woff2": "x",
      "node_modules/x/index.js": "x", "dist/app.js": "x",
    }), ref);
    expect(out.coverage).toMatchObject({ treeFiles: 6, read: 1, notRead: { binary: 3, vendored: 2 } });
  });

  it("shows a probe's own login, in a config-style pair, as information", async () => {
    const out = await scanRepository(memorySource({
      "server/aggressive/nosql.ts": 'const body = { username: "seclayer_probe", password: "seclayer_probe_9x7Kq2Lm" };\n',
    }), ref);
    const cfg = out.findings.filter((v) => /Config File/.test(v.name));
    expect(cfg.every((v) => v.severity === "info")).toBe(true);
    expect(cfg.some((v) => /deliberately fake/.test(v.name))).toBe(true);
  });

  it("reports its steps as it goes: the listing, the reading in stages, then each check", async () => {
    const many: Record<string, string> = { "supabase/migrations/001.sql": "create table t (id int);" };
    for (let i = 0; i < 250; i++) many[`src/m${i}.ts`] = `export const v${i} = ${i};`;
    const events: Array<{ kind: string; [k: string]: unknown }> = [];
    await scanRepository(memorySource(many), ref, { onProgress: (e) => events.push(e) });
    expect(events[0]).toMatchObject({ kind: "listed", treeFiles: 251, toRead: 251 });
    const reading = events.filter((e) => e.kind === "reading");
    expect(reading.map((e) => e.read)).toEqual([100, 200, 251]);
    expect(events.filter((e) => e.kind === "check").map((e) => e.name)).toEqual([
      "repository secrets", "Supabase migrations (RLS and policies)", "CI and configuration", "dangerous code patterns", "dependency vulnerabilities (OSV)",
    ]);
    // Order: listing, then reading, then checks.
    expect(events.map((e) => e.kind)).toEqual(["listed", "reading", "reading", "reading", "check", "check", "check", "check", "check"]);
  });

  it("a repository with only binary files says nothing was tested, not that it is clean", async () => {
    const out = await scanRepository(memorySource({ "static/logo.png": "x", "assets/font.woff2": "y" }), ref);
    const note = out.findings.find((v) => v.name === "GitHub source scan covered only part of the repository")!;
    expect(note.evidence).toContain("nothing was tested");
    expect(out.coverage).toMatchObject({ chosen: 0, read: 0 });
  });

  it("says a check had nothing to look at, rather than that it passed", async () => {
    const out = await scanRepository(memorySource({ "README.md": "x", "src/a.ts": "const a = 1" }), ref);
    const mig = out.checks!.find((c) => c.name.startsWith("Supabase"))!;
    expect(mig).toMatchObject({ files: 0, findings: 0, note: "no matching files in the repository" });
  });

  it("reports what it could not read: failed downloads and a truncated file list", async () => {
    const out = await scanRepository(memorySource(vulnerable, { truncated: true, fail: new Set(["src/server.ts"]) }), ref);
    const note = out.findings.find((v) => v.name === "GitHub source scan covered only part of the repository")!;
    expect(note.severity).toBe("info");
    expect(note.evidence).toContain("Could not be downloaded: 1");
    expect(note.evidence).toContain("truncated");
    expect(names(out.findings)).not.toContain("eval or new Function on Request Data");
  });

  it("has no limit on the size of the repository: every file is read, the important ones first, and secrets are found at the end of a big tree", async () => {
    const many: Record<string, string> = { ".env.production": "A=1\n", "supabase/migrations/001.sql": "create table t (id int);" };
    for (let i = 0; i < 4200; i++) many[`src/deep/module${i}.ts`] = `export const v${i} = ${i};`;
    for (let i = 0; i < 1800; i++) many[`docs/page${i}.md`] = `# page ${i}`;
    many["zzz/last.py"] = 'KEY = "sk_live_Zk3pQ8vXw2LmN7rT9yBcD4fG"\n';
    const src = memorySource(many);
    const out = await scanRepository(src, ref);
    expect(src.reads.length).toBe(Object.keys(many).length);
    expect(src.reads.slice(0, 2)).toEqual(expect.arrayContaining([".env.production", "supabase/migrations/001.sql"]));
    expect(out.coverage).toMatchObject({ read: Object.keys(many).length, leftOutByCap: 0, failedReads: 0 });
    expect(names(out.findings).some((n) => /Stripe/i.test(n) && /source repository/.test(n))).toBe(true);
    expect(names(out.findings)).not.toContain("GitHub source scan covered only part of the repository");
  });

  it("skips oversize files and dependency directories instead of reading half of them", () => {
    const { chosen, tooLarge } = chooseFiles([
      { path: "src/huge.ts", size: 12_000_000 }, { path: "node_modules/x/index.js", size: 10 }, { path: "src/ok.ts", size: 10 },
      { path: "package-lock.json", size: 3_000_000 }, { path: "dist/app.js", size: 10 },
    ]);
    expect(chosen.map((c) => c.path).sort()).toEqual(["package-lock.json", "src/ok.ts"]);
    expect(tooLarge).toBe(1);
  });

  it("leaves deliberately vulnerable test targets out, but still reads env files committed inside them", () => {
    const { chosen } = chooseFiles([
      // The layout of a real security tool's repository: a sample Supabase app with RLS off on purpose.
      { path: "test-targets/tier3-baas-supabase/supabase/migrations/0001_schema.sql", size: 10 },
      { path: "test-targets/tier3-baas-supabase/supabase/config.toml", size: 10 },
      { path: "test_targets/app/server.ts", size: 10 },
      { path: "vuln-fixtures/db.sql", size: 10 },
      { path: "vulnerable-app/index.js", size: 10 },
      { path: "test-targets/tier3-baas-supabase/.env", size: 10 },
      // The project's own files are still chosen.
      { path: "supabase/migrations/0001_init.sql", size: 10 },
      { path: "server/db.ts", size: 10 },
    ]);
    expect(chosen.map((c) => c.path).sort()).toEqual([
      "server/db.ts",
      "supabase/migrations/0001_init.sql",
      "test-targets/tier3-baas-supabase/.env",
    ]);
  });

  it("does not mistake an ordinary directory whose name merely contains 'target' for a test target", () => {
    const { chosen } = chooseFiles([{ path: "src/targets/list.ts", size: 10 }, { path: "src/retargets.ts", size: 10 }]);
    expect(chosen.map((c) => c.path).sort()).toEqual(["src/retargets.ts", "src/targets/list.ts"]);
  });

  it("a repository that cannot be opened is not a clean one", async () => {
    const out = await scanRepository(memorySource({}, { status: "not_public_or_missing" }), ref);
    expect(out).toMatchObject({ status: "not_public_or_missing", findings: [], filesRead: 0 });
  });

  it("chosen files that all fail to download is 'unreadable', not clean", async () => {
    const out = await scanRepository(memorySource({ ".env": "A=1" }, { fail: new Set([".env"]) }), ref);
    expect(out.status).toBe("unreadable");
  });
});

describe("a table whose name says nothing", () => {
  it("is information, not a flaw, when anyone may read it: a static read cannot tell public content from private rows", () => {
    const sql = `create table public.bulletin (id int); alter table public.bulletin enable row level security;\ncreate policy "r" on public.bulletin for select to anon using (true);`;
    const out = supabaseMigrationFindings([f("supabase/migrations/001.sql", sql)], ref);
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("info");
    expect(out[0]!.confidence).toBeLessThanOrEqual(40);
  });
});

describe("what the first Lovable-shaped repository showed was missing", () => {
  const sev = (v: Array<{ severity: string }>) => v.map((x) => x.severity);

  it("a public insert-only policy (a contact form) is low; an open update, delete or all-commands policy stays high", () => {
    const form = supabaseMigrationFindings([f("supabase/migrations/1_a.sql",
      `create table public.contact_messages (id int, message text);\nalter table public.contact_messages enable row level security;\ncreate policy "Anyone can send a message" on public.contact_messages for insert to anon, authenticated with check (true);`)], ref);
    expect(names(form)).toEqual([`Supabase Policy Lets Anyone Insert "contact_messages"`]);
    expect(sev(form)).toEqual(["low"]);
    const open = supabaseMigrationFindings([f("supabase/migrations/1_a.sql",
      `create table public.notes (id int);\nalter table public.notes enable row level security;\ncreate policy "all" on public.notes for all to anon using (true) with check (true);\ncreate policy "upd" on public.notes for update to anon using (true);`)], ref);
    expect(sev(open)).toEqual(["high", "high"]);
  });

  it("SECURITY DEFINER without a pinned search_path is reported; pinned before or after the body, or SECURITY INVOKER, is not", () => {
    const bad = supabaseMigrationFindings([f("supabase/migrations/1_a.sql",
      `create or replace function public.handle_new_user() returns trigger language plpgsql security definer as $$ begin insert into public.profiles(id) values (new.id); return new; end; $$;`)], ref);
    expect(names(bad)).toEqual(["Supabase Function Runs With Its Owner's Rights and No Pinned search_path"]);
    expect(bad[0]!.evidence).toContain("handle_new_user");
    const fine = supabaseMigrationFindings([
      f("supabase/migrations/1_a.sql", `create function public.a() returns trigger language plpgsql security definer set search_path = '' as $$ begin return new; end; $$;`),
      f("supabase/migrations/2_b.sql", `create function public.b() returns trigger as $fn$ begin return new; end; $fn$ language plpgsql security definer set search_path = public;`),
      f("supabase/migrations/3_c.sql", `create function public.c() returns int language sql security invoker as $$ select 1 $$;`),
      f("supabase/migrations/4_d.sql", `create function private.d() returns int language sql security definer as $$ select 1 $$;`),
    ], ref);
    expect(names(fine)).toEqual([]);
  });

  it("a view without security_invoker is reported (medium over an RLS table, low otherwise); with it, not", () => {
    const rls = supabaseMigrationFindings([f("supabase/migrations/1_a.sql",
      `create table public.orders (id int, user_id uuid);\nalter table public.orders enable row level security;\ncreate view public.order_summary as select id, user_id from public.orders;`)], ref);
    expect(names(rls)).toEqual(["Supabase View Bypasses Row Level Security (no security_invoker)"]);
    expect(sev(rls)).toEqual(["medium"]);
    const norls = supabaseMigrationFindings([f("supabase/migrations/1_a.sql",
      `create table public.orders (id int);\ncreate view public.v as select id from public.orders;`)], ref);
    expect(sev(norls.filter((v) => v.name.startsWith("Supabase View")))).toEqual(["low"]);
    const fine = supabaseMigrationFindings([f("supabase/migrations/1_a.sql",
      `create table public.orders (id int, user_id uuid);\nalter table public.orders enable row level security;\ncreate view public.order_summary with (security_invoker = true) as select id from public.orders;`)], ref);
    expect(names(fine)).toEqual([]);
  });

  it("a storage SELECT policy open to anon with no owner check is reported; owner-scoped, authenticated-only or insert-only is not", () => {
    const bad = supabaseMigrationFindings([f("supabase/migrations/1_a.sql",
      `create policy "Avatar images are publicly accessible" on storage.objects for select using (bucket_id = 'avatars');`)], ref);
    expect(names(bad)).toEqual([`Supabase Storage Policy Lets Anyone List and Read Bucket "avatars"`]);
    const fine = supabaseMigrationFindings([f("supabase/migrations/1_a.sql", [
      `create policy "own" on storage.objects for select to authenticated using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);`,
      `create policy "up" on storage.objects for insert to authenticated with check (bucket_id = 'avatars');`,
      `create policy "anon but owned" on storage.objects for select to anon using (bucket_id = 'x' and owner = auth.uid());`,
    ].join("\n"))], ref);
    expect(names(fine)).toEqual([]);
  });

  it("verify_jwt = false: a function that checks the Stripe signature is fine; one that does not is a high-severity unsigned webhook; the comment 'no signature check' does not count", () => {
    const toml = f("supabase/config.toml", "[functions.stripe-webhook]\nverify_jwt = false\n");
    const signed = f("supabase/functions/stripe-webhook/index.ts", `const event = await stripe.webhooks.constructEventAsync(body, req.headers.get("Stripe-Signature"), secret);`);
    expect(ciConfigFindings([toml, signed], ref)).toEqual([]);
    const unsigned = f("supabase/functions/stripe-webhook/index.ts", `// Accepts any POST as a Stripe event: there is no signature check.\nconst event = await req.json();`);
    const out = ciConfigFindings([toml, unsigned], ref);
    expect(names(out)).toEqual(["Webhook Edge Function Accepts Unsigned Requests"]);
    expect(sev(out)).toEqual(["high"]);
    // Not a webhook by name, no auth in code: the generic finding. Code not read: the generic finding too.
    const inv = f("supabase/config.toml", "[functions.get-invoice]\nverify_jwt = false\n");
    expect(names(ciConfigFindings([inv, f("supabase/functions/get-invoice/index.ts", `const { data } = await admin.from("invoices").select("*");`)], ref))).toEqual(["Supabase Edge Functions Configured Without JWT Verification"]);
    expect(names(ciConfigFindings([inv], ref))).toEqual(["Supabase Edge Functions Configured Without JWT Verification"]);
    // The caller's JWT resolved to a user is authentication.
    expect(ciConfigFindings([inv, f("supabase/functions/get-invoice/index.ts", `const { data: u } = await supabase.auth.getUser();`)], ref)).toEqual([]);
  });
});

describe("found in real repositories: the report", () => {
  it("shows a development database password as information, and a generated one as the high finding it is", async () => {
    const out = await scanRepository(memorySource({
      "docker-compose.yml": "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: complyscan\n",
      "deploy/docker-compose.prod.yml": "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: Xk9fQ2mLp8Zr4Tv7Nc1Wb6Hs\n",
    }), ref);
    const dev = out.findings.filter((v) => /looks like a development default/.test(v.name));
    const real = out.findings.filter((v) => /Hardcoded Secret in Config File \(in source repository\)/.test(v.name));
    expect(dev).toHaveLength(1);
    expect(dev[0]!.severity).toBe("info");
    expect(dev[0]!.evidence).toContain("docker-compose.yml");
    expect(real).toHaveLength(1);
    expect(real[0]!.severity).toBe("high");
    expect(real[0]!.evidence).toContain("deploy/docker-compose.prod.yml");
  });

  it("does not report fetch credentials modes in a front-end script", async () => {
    const out = await scanRepository(memorySource({ "runner/ui/app.js": 'const r = await fetch("/api", { credentials: "same-origin", headers: { a: "b" } });\n' }), ref);
    expect(out.findings.filter((v) => /Secret|Password|Credential/i.test(v.name))).toEqual([]);
  });
});

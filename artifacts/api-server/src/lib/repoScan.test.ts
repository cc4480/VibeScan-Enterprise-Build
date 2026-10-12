import { describe, it, expect, vi } from "vitest";

// OSV is the only network the dependency check uses; the answer is decided here.
const osv = vi.hoisted(() => ({ vulnerable: new Set<string>() }));
vi.mock("./cveCheck", async (orig) => {
  const real = await orig<typeof import("./cveCheck")>();
  return {
    ...real,
    queryOsv: async (name: string, version: string) =>
      osv.vulnerable.has(`${name}@${version}`)
        ? [{ id: "GHSA-test-0001", aliases: ["CVE-2026-0001"], summary: "Prototype pollution", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }], affected: [{ ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] }]
        : [],
  };
});

import { supabaseMigrationFindings } from "./repoCheckSupabase";
import { ciConfigFindings, functionsWithoutJwt } from "./repoCheckCi";
import { codePatternFindings } from "./repoCheckCode";
import { lockedPackages, directDependencies } from "./repoCheckDeps";
import { scanRepository, chooseFiles, MAX_FILES } from "./repoScan";
import type { RepoSource } from "./repoSource";
import type { RepoFile, RepoRef } from "./repoFinding";

/**
 * The repository scan: Supabase migrations, CI and configuration, a few dangerous code patterns, dependencies, secrets.
 * Every rule has a clean twin: the same file done correctly, which must report nothing.
 */

const ref: RepoRef = { owner: "acme", repo: "taskflow" };
const f = (path: string, content: string): RepoFile => ({ path, content });
const names = (x: Array<{ name: string }>) => x.map((v) => v.name);

describe("Supabase migrations", () => {
  const m = (n: string, sql: string) => f(`supabase/migrations/${n}.sql`, sql);

  it("flags tables that are created and never given RLS", () => {
    const out = supabaseMigrationFindings([m("001", `create table public.profiles (id uuid primary key, email text);\ncreate table app_secrets (k text, v text);`)], ref);
    expect(out).toHaveLength(1);
    expect(out[0]!.name).toBe("Supabase Tables Created Without Row Level Security");
    expect(out[0]!.severity).toBe("high");
    expect(out[0]!.evidence).toContain("profiles, app_secrets");
    expect(out[0]!.evidence).toContain("supabase/migrations/001.sql");
  });

  it("clean twin: RLS enabled in the same or a later migration, with owner policies, reports nothing", () => {
    const out = supabaseMigrationFindings([
      m("001", `create table public.profiles (id uuid primary key, user_id uuid);\ncreate table public.tasks (id int, user_id uuid);`),
      m("002", `alter table public.profiles enable row level security;\nALTER TABLE "public"."tasks" ENABLE ROW LEVEL SECURITY;\n` +
        `create policy "own" on public.profiles for select to authenticated using ((select auth.uid()) = user_id);`),
    ], ref);
    expect(out).toEqual([]);
  });

  it("applies migrations in order: a later disable or a drop settles an earlier enable", () => {
    expect(names(supabaseMigrationFindings([m("001", `create table t1 (id int); alter table t1 enable row level security;`), m("002", `alter table t1 disable row level security;`)], ref))).toContain("Supabase Tables Created Without Row Level Security");
    expect(supabaseMigrationFindings([m("001", `create table t1 (id int);`), m("002", `drop table t1;`)], ref)).toEqual([]);
  });

  it("ignores comments and tables outside the public schema", () => {
    expect(supabaseMigrationFindings([m("001", `-- create table ghost (id int);\n/* create table ghost2 (id int); */\ncreate table private.audit (id int);\ncreate table auth.extra (id int);`)], ref)).toEqual([]);
  });

  it("flags a policy that lets anyone write, and one that lets anyone read a private-looking table", () => {
    const base = `create table public.orders (id int); alter table public.orders enable row level security;\ncreate table public.products (id int); alter table public.products enable row level security;\n`;
    const writes = supabaseMigrationFindings([m("001", base + `create policy "all" on public.orders for all to anon using (true) with check (true);`)], ref);
    expect(names(writes)).toEqual([`Supabase Policy Lets Anyone Read and Write "orders"`]);
    expect(writes[0]!.severity).toBe("high");
    const reads = supabaseMigrationFindings([m("001", base + `create policy "read" on public.orders for select using (true);`)], ref);
    expect(names(reads)).toEqual([`Supabase Policy Lets Anyone Read "orders"`]);
    expect(reads[0]!.evidence).toContain("To: public");
  });

  it("clean twin: a public-by-design table may be read by anyone; a policy scoped to the owner is fine", () => {
    const sql = `create table public.products (id int); alter table public.products enable row level security;\n` +
      `create policy "public read" on public.products for select to anon, authenticated using (true);\n` +
      `create table public.notes (id int, user_id uuid); alter table public.notes enable row level security;\n` +
      `create policy "own" on public.notes for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);`;
    expect(supabaseMigrationFindings([m("001", sql)], ref)).toEqual([]);
  });

  it("flags a permissive policy for every signed-in user, on a table that is not public content", () => {
    const sql = `create table public.documents (id int, body text); alter table public.documents enable row level security;\ncreate policy "any" on public.documents for select to authenticated using (true);`;
    const out = supabaseMigrationFindings([m("001", sql)], ref);
    expect(names(out)).toEqual([`Supabase Policy Lets Every Signed-In User Reach All Rows of "documents"`]);
    expect(out[0]!.severity).toBe("medium");
  });

  it("reports nothing for a repository with no migrations", () => {
    expect(supabaseMigrationFindings([f("src/app.ts", "create table x")], ref)).toEqual([]);
  });
});

describe("CI and configuration", () => {
  it("flags a pull_request_target workflow that checks out the PR's code", () => {
    const yml = `on:\n  pull_request_target:\n    types: [opened]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n      - run: npm test\n`;
    expect(names(ciConfigFindings([f(".github/workflows/pr.yml", yml)], ref))).toContain("GitHub Actions Workflow Runs Pull-Request Code With Repository Secrets");
  });

  it("clean twin: pull_request_target that does not check out the PR head, and a plain pull_request build", () => {
    const safe = `on:\n  pull_request_target:\njobs:\n  label:\n    steps:\n      - uses: actions/labeler@v5\n`;
    const plain = `on: [pull_request]\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`;
    expect(ciConfigFindings([f(".github/workflows/a.yml", safe), f(".github/workflows/b.yml", plain)], ref)).toEqual([]);
  });

  it("flags a run step that interpolates an issue title, and passes it when it goes through env", () => {
    const bad = `jobs:\n  x:\n    steps:\n      - run: echo "New issue \${{ github.event.issue.title }}"\n`;
    expect(names(ciConfigFindings([f(".github/workflows/i.yml", bad)], ref))).toEqual(["GitHub Actions Shell Step Interpolates Attacker-Controlled Text"]);
    const good = `jobs:\n  x:\n    steps:\n      - env:\n          TITLE: \${{ github.event.issue.title }}\n        run: echo "New issue $TITLE"\n`;
    expect(ciConfigFindings([f(".github/workflows/i.yml", good)], ref)).toEqual([]);
  });

  it("flags write-all permissions; clean twin scopes them", () => {
    expect(names(ciConfigFindings([f(".github/workflows/p.yml", "permissions: write-all\njobs: {}\n")], ref))).toEqual(["GitHub Actions Workflow Requests write-all Permissions"]);
    expect(ciConfigFindings([f(".github/workflows/p.yml", "permissions:\n  contents: read\njobs: {}\n")], ref)).toEqual([]);
  });

  it("flags a Dockerfile that bakes a credential in, never writing the value out", () => {
    const out = ciConfigFindings([f("Dockerfile", "FROM node:22\nENV STRIPE_SECRET_KEY=sk_live_Zk3pQ8vXw2LmN7rT9yBc\n")], ref);
    expect(names(out)).toEqual(["Dockerfile Bakes a Credential Into the Image"]);
    expect(out[0]!.evidence).not.toContain("Zk3pQ8vXw2LmN7rT9yBc");
  });

  it("clean twin: ordinary ENV lines, a secret passed at run time, placeholders", () => {
    const df = "FROM node:22\nENV NODE_ENV=production\nARG API_TOKEN\nENV SESSION_SECRET=$SESSION_SECRET\nENV DB_PASSWORD=changeme-in-dev\n";
    expect(ciConfigFindings([f("Dockerfile", df)], ref)).toEqual([]);
  });

  it("reads verify_jwt = false per function from config.toml", () => {
    const toml = `[functions.stripe-webhook]\nverify_jwt = false\n\n[functions.get-invoice]\nverify_jwt = false # TODO\n\n[functions.safe]\nverify_jwt = true\n\n[auth]\nverify_jwt = false\n`;
    expect(functionsWithoutJwt(toml)).toEqual(["stripe-webhook", "get-invoice"]);
    const out = ciConfigFindings([f("supabase/config.toml", toml)], ref);
    expect(out[0]!.name).toBe("Supabase Edge Functions Configured Without JWT Verification");
    expect(out[0]!.evidence).toContain("stripe-webhook, get-invoice");
    expect(ciConfigFindings([f("supabase/config.toml", "[functions.safe]\nverify_jwt = true\n")], ref)).toEqual([]);
  });
});

describe("dangerous code patterns", () => {
  it("flags a secret behind a client-exposed prefix, in an env file and in code", () => {
    const env = codePatternFindings([f(".env.production", `VITE_SUPABASE_URL=https://x.supabase.co\nVITE_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiJ9.abc123def456\n`)], ref);
    expect(names(env)).toEqual(["Secret Exposed Through a Client-Side Environment Prefix"]);
    expect(env[0]!.evidence).toContain("VITE_SUPABASE_SERVICE_ROLE_KEY");
    expect(env[0]!.evidence).not.toContain("abc123def456");
    const code = codePatternFindings([f("src/lib/admin.ts", `const k = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;`)], ref);
    expect(names(code)).toEqual(["Secret Exposed Through a Client-Side Environment Prefix"]);
  });

  it("clean twin: public-by-design names, empty or placeholder values, an example file, server-only names", () => {
    expect(codePatternFindings([
      f(".env.production", `VITE_SUPABASE_PUBLISHABLE_KEY=eyJhbGciOiJIUzI1NiJ9.abc123\nVITE_RECAPTCHA_SITE_KEY=6Lc123456789\nVITE_API_SECRET=\n`),
      f(".env.example", `VITE_SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here`),
      f("src/lib/supabase.ts", `createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY)`),
      f("supabase/functions/x/index.ts", `Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")`),
    ], ref)).toEqual([]);
  });

  it("flags eval on request data, SQL built from it, wildcard CORS with credentials, TLS verification off", () => {
    const out = codePatternFindings([
      f("server/a.ts", "app.post('/x', (req, res) => { eval(req.body.code) })"),
      f("server/b.ts", "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)"),
      f("server/c.ts", "app.use(cors({ origin: true, credentials: true }))"),
      f("server/d.ts", "const agent = new https.Agent({ rejectUnauthorized: false })"),
    ], ref);
    expect(names(out).sort()).toEqual(["CORS Allows Any Origin With Credentials", "SQL Built From Request Data by String Interpolation", "TLS Certificate Verification Disabled", "eval or new Function on Request Data"]);
  });

  it("clean twin: parameterised SQL, an origin allow-list, eval of a literal, tests and dependencies", () => {
    expect(codePatternFindings([
      f("server/b.ts", "db.query('SELECT * FROM users WHERE id = $1', [req.params.id])"),
      f("server/c.ts", "app.use(cors({ origin: ['https://app.acme.test'], credentials: true }))"),
      f("server/a.ts", "const f = new Function('a', 'return a + 1')"),
      f("src/x.test.ts", "eval(req.body.code)"),
      f("node_modules/lib/index.js", "eval(req.body.code)"),
    ], ref)).toEqual([]);
  });
});

describe("dependencies", () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, "node_modules/lodash": { version: "4.17.20" }, "node_modules/react": { version: "19.0.0" }, "node_modules/a/node_modules/lodash": { version: "4.17.15" }, "node_modules/linked": { link: true } } });

  it("reads exact versions from a lockfile and a manifest, never a range", () => {
    expect(lockedPackages(lock)).toEqual([{ name: "lodash", version: "4.17.20" }, { name: "react", version: "19.0.0" }, { name: "lodash", version: "4.17.15" }]);
    expect(directDependencies(JSON.stringify({ dependencies: { a: "1.2.3", b: "^2.0.0" }, devDependencies: { c: "3.0.0" } }))).toEqual([{ name: "a", version: "1.2.3" }, { name: "c", version: "3.0.0" }]);
    expect(lockedPackages("not json")).toEqual([]);
  });

  it("reports a vulnerable locked package with the file that named it, and nothing for clean versions", async () => {
    const { dependencyFindings } = await import("./repoCheckDeps");
    osv.vulnerable = new Set(["lodash@4.17.20"]);
    const bad = await dependencyFindings([f("package-lock.json", lock), f("package.json", JSON.stringify({ dependencies: { lodash: "^4.17.0" } }))]);
    expect(bad.findings).toHaveLength(1);
    expect(`${bad.findings[0]!.evidence}${bad.findings[0]!.description}`).toMatch(/lodash/);
    expect(bad.source).toBe("package-lock.json");
    osv.vulnerable = new Set();
    expect((await dependencyFindings([f("package-lock.json", lock)])).findings).toEqual([]);
  });
});

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
    expect(out.coverage).toMatchObject({ treeFiles: 6, read: 5, failedReads: 0 });
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

  it("is bounded: a huge tree is capped, prioritised, and the cap is reported", async () => {
    const many: Record<string, string> = { ".env.production": "A=1\n", "supabase/migrations/001.sql": "create table t (id int);" };
    for (let i = 0; i < 900; i++) many[`src/deep/module${i}.ts`] = `export const v${i} = ${i};`;
    const src = memorySource(many);
    const out = await scanRepository(src, ref);
    expect(src.reads.length).toBeLessThanOrEqual(MAX_FILES);
    expect(src.reads.slice(0, 2)).toEqual(expect.arrayContaining([".env.production", "supabase/migrations/001.sql"]));
    expect(out.coverage!.leftOutByCap).toBeGreaterThan(500);
    expect(out.findings.find((v) => v.name === "GitHub source scan covered only part of the repository")!.evidence).toMatch(/Left out by the file and size limits: \d+/);
  });

  it("skips oversize files and dependency directories instead of reading half of them", () => {
    const { chosen, tooLarge } = chooseFiles([
      { path: "src/huge.ts", size: 5_000_000 }, { path: "node_modules/x/index.js", size: 10 }, { path: "src/ok.ts", size: 10 },
      { path: "package-lock.json", size: 3_000_000 }, { path: "dist/app.js", size: 10 },
    ]);
    expect(chosen.map((c) => c.path).sort()).toEqual(["package-lock.json", "src/ok.ts"]);
    expect(tooLarge).toBe(1);
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

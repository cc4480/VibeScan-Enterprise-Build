import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { startOsvStub } from "./osvStub.testkit";
import { osvCache } from "./cveCheckOsv";

// OSV is the only network the dependency check uses. It is a real local server that answers like OSV.dev
// (lib/osvStub.testkit.ts), so the real client's queries, cache and error handling all run; the answers are decided here.
const osv = await startOsvStub();
beforeEach(() => osvCache.clear()); // a verdict cached by an earlier test would otherwise answer for this one
afterAll(() => osv.stop());

import { supabaseMigrationFindings } from "./repoCheckSupabase";
import { ciConfigFindings, functionsWithoutJwt } from "./repoCheckCi";
import { codePatternFindings } from "./repoCheckCode";
import { lockedPackages, directDependencies } from "./repoCheckDeps";
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
    const out = ciConfigFindings([f("Dockerfile", "FROM node:22\nENV STRIPE_SECRET_KEY=sk_live_Zk3pQ8vXw2LmN7rT9yBc\nUSER node\n")], ref);
    expect(names(out)).toEqual(["Dockerfile Bakes a Credential Into the Image"]);
    expect(out[0]!.evidence).not.toContain("Zk3pQ8vXw2LmN7rT9yBc");
  });

  it("clean twin: ordinary ENV lines, a secret passed at run time, placeholders", () => {
    const df = "FROM node:22\nENV NODE_ENV=production\nARG API_TOKEN\nENV SESSION_SECRET=$SESSION_SECRET\nENV DB_PASSWORD=changeme-in-dev\nUSER node\n";
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
    // The same file is also a committed .env that sets a secret-named variable: both are true.
    expect(names(env)).toEqual(["Secret Exposed Through a Client-Side Environment Prefix", "Environment File Committed to the Repository"]);
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
      // The name inside a string is documentation or a pattern list, not a read of the variable.
      f("src/lib/patterns.ts", `{ description: "Never name a variable VITE_DATABASE_URL or VITE_SERVICE_ROLE_KEY; the build inlines it." }`),
    ], ref)).toEqual([]);
  });

  it("TLS verification off: a flaw when nothing says otherwise, information when the code beside it says it is deliberate or reads the certificate", () => {
    const bare = codePatternFindings([f("src/api.ts", `const agent = new https.Agent({ rejectUnauthorized: false });\nawait fetch(url, { agent, headers: { Authorization: token } });`)], ref);
    expect(bare.map((v) => v.severity)).toEqual(["medium"]);
    const said = codePatternFindings([
      f("src/probe.ts", `// The cert is observed, not trusted: this host is operator-scoped.\nrejectUnauthorized: false,`),
      f("src/expiry.ts", `const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => { const c = socket.getPeerCertificate(); });`),
    ], ref);
    expect(said.map((v) => v.severity)).toEqual(["info", "info"]);
    expect(said[0]!.evidence).toContain("shown as information");
    // The setting named in a comment first, then used where the certificate is read: judged by the code line, not the comment.
    const commentFirst = codePatternFindings([f("server/tlsProbe.ts", [
      "// rejectUnauthorized:false so we can still INSPECT an expired cert (that's the point)",
      "const socket = tls.connect(",
      "  { host, port, rejectUnauthorized: false },",
      "  () => { const cert = socket.getPeerCertificate(); },",
      ");",
    ].join("\n"))], ref);
    expect(commentFirst.map((v) => v.severity)).toEqual(["info"]);
    // Only a comment names it: nothing is switched off.
    expect(codePatternFindings([f("src/n.ts", "// never set rejectUnauthorized: false in production\nconst x = 1;")], ref)).toEqual([]);
    // A comment far from the line does not excuse it.
    const far = codePatternFindings([f("src/a.ts", `// deliberate choice of library\n${"const x = 1;\n".repeat(20)}rejectUnauthorized: false`)], ref);
    expect(far.map((v) => v.severity)).toEqual(["medium"]);
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
    expect(lockedPackages(lock)).toEqual([{ name: "lodash", version: "4.17.20", ecosystem: "npm" }, { name: "react", version: "19.0.0", ecosystem: "npm" }, { name: "lodash", version: "4.17.15", ecosystem: "npm" }]);
    expect(directDependencies(JSON.stringify({ dependencies: { a: "1.2.3", b: "^2.0.0" }, devDependencies: { c: "3.0.0" } }))).toEqual([{ name: "a", version: "1.2.3", ecosystem: "npm" }, { name: "c", version: "3.0.0", ecosystem: "npm", dev: true }]);
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
    osvCache.clear(); // the first answer is cached, as in a real scan; a second scan of a fixed package starts fresh
    expect((await dependencyFindings([f("package-lock.json", lock)])).findings).toEqual([]);
  });
});

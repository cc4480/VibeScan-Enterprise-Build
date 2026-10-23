import { describe, it, expect } from "vitest";
import { scanContent } from "./jsScanner";
import { scanConfigSecrets } from "./configSecrets";
import { codePatternFindings } from "./repoCheckCode";
import { supabaseExtraFindings } from "./repoCheckSupabaseExtra";
import { supabaseMigrationFindings } from "./repoCheckSupabase";
import { infraFindings } from "./repoCheckInfra";
import { isTestOrExamplePath } from "./repoFinding";
import type { RepoFile, RepoRef } from "./repoFinding";

/**
 * Every case here was a false positive reported on a real, well-known public project when the scanner was run over a
 * set of them (Flask, FastAPI's full-stack template, Vercel's Next.js subscription template, Express). Each is the
 * shape that project has, so the fix cannot drift away from the thing that was wrong.
 */
const ref: RepoRef = { owner: "acme", repo: "app" };
const f = (path: string, content: string): RepoFile => ({ path, content });
const keys = (path: string, content: string) => scanConfigSecrets(path, content).map((h) => h.key);

describe("values that are words, not secrets", () => {
  it("a quoted phrase or a lowercase identifier in source code is a label (Flask, FastAPI, Vercel templates)", () => {
    expect(keys("src/flask/config.py", `    "SECRET_KEY": "development key",`)).toEqual([]);
    expect(keys("frontend/src/components/ui/password-input.tsx", `const label = { password: "Show password" };`)).toEqual([]);
    expect(keys("utils/auth-helpers/settings.ts", `const settings = { password_signin: "email_signin" };`)).toEqual([]);
  });

  it("clean twin: a generated-looking value in the same positions is still reported", () => {
    expect(keys("src/config.py", `    "SECRET_KEY": "Xk9fQ2mLp8Zr4Tv7Nc1Wb6Hs",`)).toEqual(["SECRET_KEY"]);
  });

  it("the template's own placeholder (changethis, change-me, replace_me) is not a value", () => {
    expect(keys(".env", `SECRET_KEY=changethis\nFIRST_SUPERUSER_PASSWORD=changethis\nPOSTGRES_PASSWORD=change-me\nAPI_TOKEN=replace_me\n`)).toEqual([]);
    expect(codePatternFindings([f(".env", `SECRET_KEY=changethis\nPOSTGRES_PASSWORD=changethis\n`)], ref)).toEqual([]);
  });

  it("a template variable ({{ password }}) is where a value goes, not a value", () => {
    const tsx = `export default function NewAccount({\n  project_name = "{{ project_name }}",\n  password = "{{ password }}",\n}) {}`;
    expect(scanContent(tsx).map((h) => h.pattern.name)).not.toContain("Hardcoded Password in Source Code");
    expect(scanContent(`const pwd = "${"${DB_PASSWORD}"}x"`).map((h) => h.pattern.name)).not.toContain("Hardcoded Password in Source Code");
  });
});

describe("prose is not source", () => {
  it("a changelog or README is treated like an example file", () => {
    expect(isTestOrExamplePath("History.md")).toBe(true);
    expect(isTestOrExamplePath("docs/guide.rst")).toBe(true);
    expect(isTestOrExamplePath("src/server.ts")).toBe(false);
  });
});

describe("the Supabase sign-up trigger", () => {
  const trigger = `create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = '' as $$\nbegin\n  insert into public.users (id, full_name, avatar_url) values (new.id, new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'avatar_url');\n  return new;\nend;\n$$;`;
  const sql = (c: string) => [f("supabase/migrations/20230530034630_init.sql", c)];

  it("copying a display name out of the metadata decides no access", () => {
    expect(supabaseExtraFindings(sql(trigger), ref).map((v) => v.name)).toEqual([]);
  });

  it("clean twin: a function that compares the metadata with a role is still reported", () => {
    const authz = `create function public.is_admin() returns boolean language sql as $$ select (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin' $$;`;
    expect(supabaseExtraFindings(sql(authz), ref).map((v) => v.name)).toEqual(["Supabase Access Decided From user_metadata"]);
  });
});

describe("compose files that are meant for the developer's machine", () => {
  it("a database port in an override file is information, and a read-only socket (a reverse proxy) is low", () => {
    const override = infraFindings(f("compose.override.yml", `services:\n  db:\n    ports:\n      - "5432:5432"\n`), ref);
    expect(override[0]).toMatchObject({ severity: "info" });
    const proxy = infraFindings(f("compose.yml", `services:\n  proxy:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro\n`), ref);
    expect(proxy[0]).toMatchObject({ name: "Compose Service Mounts the Docker Socket", severity: "low" });
  });

  it("clean twin: the same port in the main compose file, and a writable socket, keep their rating", () => {
    expect(infraFindings(f("compose.yml", `services:\n  db:\n    ports:\n      - "5432:5432"\n`), ref)[0]).toMatchObject({ severity: "medium" });
    expect(infraFindings(f("compose.yml", `services:\n  a:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n`), ref)[0]).toMatchObject({ severity: "medium" });
  });
});

describe("found when the scanner was run over public projects, round two", () => {
  it("a token written to a file, or piped to a tool, is not printed to the log (create-t3-app)", async () => {
    const { ciConfigFindings } = await import("./repoCheckCi");
    const wf = (run: string) => ciConfigFindings([f(".github/workflows/p.yml", `jobs:\n  a:\n    steps:\n      - ${run}\n`)], ref).map((v) => v.name);
    expect(wf(`run: echo "//registry.npmjs.org/:_authToken=\${{ secrets.NPM_TOKEN }}" > ~/.npmrc`)).toEqual([]);
    expect(wf(`run: echo "\${{ secrets.TOKEN }}" | docker login --password-stdin`)).toEqual([]);
    // Clean twin: echoed to the log.
    expect(wf(`run: echo "token is \${{ secrets.TOKEN }}"`)).toEqual(["GitHub Actions Step Prints a Secret"]);
  });

  it("an Algolia DocSearch key beside its index name is public by design (create-t3-app docs)", () => {
    const docs = `export const config = {\n  docSearch: {\n    appId: "R2IYF7ETH7",\n    apiKey: "892c46a8b2c2c3b1d4f5e6a7b8c95e40",\n    indexName: "create-t3-app",\n  },\n};`;
    expect(keys("www/src/config.ts", docs)).toEqual([]);
    // Clean twin: the same key with no search context is still reported.
    expect(keys("www/src/client.ts", `export const c = {\n  apiKey: "892c46a8b2c2c3b1d4f5e6a7b8c95e40",\n};`)).toEqual(["apiKey"]);
  });

  it("an env file whose values are references to other variables is not a committed secret (FastAPI template)", () => {
    const env = `DATABASE_URL=postgresql://\${POSTGRES_USER}:\${POSTGRES_PASSWORD}@db/app\n`;
    expect(codePatternFindings([f(".env", env)], ref)).toEqual([]);
  });

  it("a script held in an all-caps constant is static (ai-chatbot)", () => {
    expect(codePatternFindings([f("app/layout.tsx", `<script dangerouslySetInnerHTML={{ __html: THEME_COLOR_SCRIPT }} />`)], ref)).toEqual([]);
    expect(codePatternFindings([f("app/post.tsx", `<div dangerouslySetInnerHTML={{ __html: post.body }} />`)], ref).map((v) => v.name)).toEqual(["dangerouslySetInnerHTML With Unsanitised Content"]);
  });
});

describe("round three: Go, monorepos and repeats", () => {
  // A small repository held in memory, read through the real scan.
  async function scan(files: Record<string, string>) {
    const { scanRepository } = await import("./repoScan");
    const source = {
      via: "public" as const,
      open: async () => ({ ok: true as const, branch: "main", truncated: false, tree: Object.keys(files).map((p) => ({ path: p, size: files[p]!.length })) }),
      read: async (p: string) => files[p] ?? null,
    };
    return scanRepository(source, ref);
  }

  it("a Go test file is a test file, and Go constants that name a token are labels (PocketBase)", async () => {
    const out = await scan({
      "core/record_tokens.go": `const (\n\tTokenTypeVerification = "verification"\n\tTokenClaimNewEmail = "newEmail"\n\tFieldNameTokenKey = "tokenKey"\n)\n`,
      "core/record_tokens_test.go": `package core\nvar secret = "Xk9fQ2mLp8Zr4Tv7Nc1Wb6Hs"\nvar jwtToken = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyMzQ1Njc4In0.c2lnbmF0dXJlLXNpZ25hdHVyZS1zaWduYXR1cmU"\nvar ip = "192.168.1.10"\n`,
    });
    const real = out.findings.filter((v) => v.severity !== "info" && v.category !== "Scan Coverage");
    expect(real.map((v) => v.name)).toEqual([]);
    expect(out.findings.some((v) => /test or example file/.test(v.name))).toBe(true);
  });

  it("clean twin: the same secret in a non-test Go file is reported", async () => {
    const out = await scan({ "server/config.go": `package server\nvar jwtSecret = "Xk9fQ2mLp8Zr4Tv7Nc1Wb6Hs"\n` });
    expect(out.findings.filter((v) => v.severity !== "info" && /Secret|Token|Password/i.test(v.name)).length).toBeGreaterThan(0);
  });

  it("a Supabase project under test/ or example/ is a fixture, judged apart from the real one (supabase-js)", async () => {
    const out = await scan({
      "supabase/migrations/001_app.sql": `create table public.orders (id uuid primary key);\nalter table public.orders enable row level security;\n`,
      "packages/lib/test/supabase/migrations/001_fixture.sql": `create table public.todos (id uuid primary key);\n`,
      "packages/lib/example/supabase/migrations/001_example.sql": `create table public.messages (id uuid primary key);\ncreate policy "all" on public.messages for select to anon using (true);\n`,
    });
    const rls = out.findings.filter((v) => /Without Row Level Security|Lets Anyone/.test(v.name));
    expect(rls.length).toBeGreaterThan(0);
    expect(rls.every((v) => v.severity === "info")).toBe(true);
    expect(rls.every((v) => /test or example file/.test(v.name))).toBe(true);
  });

  it("clean twin: the real project's missing RLS is still reported at full strength, beside fixtures", async () => {
    const out = await scan({
      "supabase/migrations/001_app.sql": `create table public.orders (id uuid primary key);\n`,
      "packages/lib/test/supabase/migrations/001_fixture.sql": `create table public.todos (id uuid primary key);\n`,
    });
    const real = out.findings.filter((v) => /Without Row Level Security \(in source|Without Row Level Security$/.test(v.name) || (/Without Row Level Security/.test(v.name) && v.severity !== "info"));
    expect(real).toHaveLength(1);
    expect(real[0]!.evidence).toContain("supabase/migrations/001_app.sql");
    expect(real[0]!.evidence).not.toContain("todos");
  });

  it("a hygiene finding that repeats across files is one finding listing them all (create-t3-app)", async () => {
    const wf = (n: number) => `jobs:\n  a:\n    steps:\n      - uses: some-org/some-action@v${n}\n`;
    const out = await scan({ ".github/workflows/a.yml": wf(1), ".github/workflows/b.yml": wf(2), ".github/workflows/c.yml": wf(3) });
    const pinned = out.findings.filter((v) => /Pinned to a Mutable Tag/.test(v.name));
    expect(pinned).toHaveLength(1);
    for (const file of ["a.yml", "b.yml", "c.yml"]) expect(pinned[0]!.evidence).toContain(file);
    expect(pinned[0]!.description).toMatch(/3 files/);
  });

  it("higher severities and dependencies are never merged", async () => {
    const { mergeSameName } = await import("./repoPostProcess");
    const mk = (severity: "high" | "low", file: string) => ({ id: file, name: "Same Name", severity, category: "Injection", description: "d", evidence: `Repository: a/b\nFile: ${file}`, solution: "s", cweId: null, cvssScore: 0 }) as never;
    expect(mergeSameName([mk("high", "a.ts"), mk("high", "b.ts")])).toHaveLength(2);
    expect(mergeSameName([mk("low", "a.ts"), mk("low", "b.ts")])).toHaveLength(1);
  });
});

describe("the Agent-Mesh report: a local development stack is not a published server", () => {
  it("a database port whose password defaults to a development value is information (docker-compose.yml with ${DB_PASSWORD:-localdev123})", () => {
    const compose = `services:\n  postgres:\n    environment:\n      POSTGRES_PASSWORD: \${DB_PASSWORD:-localdev123}\n    ports:\n      - "5432:5432"\n`;
    expect(infraFindings(f("docker-compose.yml", compose), ref)[0]).toMatchObject({ severity: "info" });
  });

  it("clean twin: the same port with a password that has no development default stays medium", () => {
    const compose = `services:\n  postgres:\n    environment:\n      POSTGRES_PASSWORD: \${DB_PASSWORD:?set-it}\n    ports:\n      - "5432:5432"\n`;
    expect(infraFindings(f("docker-compose.yml", compose), ref)[0]).toMatchObject({ severity: "medium" });
  });

  it("an example env file whose value names itself local is a placeholder, not a hardcoded secret (.env.example)", () => {
    expect(keys(".env.example", "RAW_DATA_ACCESS_KEY_ENV=local-7fQ2kXv9Lm4Rt8Wz3Nb6Hy1Pc5Ds0Jq\n")).toEqual([]);
  });

  it("clean twin: a generated-looking value in the same example file is still reported", () => {
    expect(keys(".env.example", "RAW_DATA_ACCESS_KEY_ENV=Xk9fQ2mLp8Zr4Tv7Nc1Wb6Hs0Gd3Ey\n")).toEqual(["RAW_DATA_ACCESS_KEY_ENV"]);
  });
});

describe("the create-t3-app report: a DocSearch search key is public by design", () => {
  const apiKeyFindings = (content: string) => scanContent(content).filter((h) => h.pattern.name === "API Key in Client Code (verify restrictions)");

  it("an apiKey beside indexName (Algolia DocSearch, www/src/config.ts) is not reported", () => {
    const config = `export const ALGOLIA = {\n  indexName: "t3-docs",\n  appId: "ABC123DEF4",\n  apiKey: "a1b2c3d4e5f6g7h8i9j0k1l2",\n};\n`;
    expect(apiKeyFindings(config)).toEqual([]);
  });

  it("clean twin: an apiKey with no search index beside it is still reported", () => {
    const client = `export const service = {\n  endpoint: "https://api.example.com",\n  apiKey: "a1b2c3d4e5f6g7h8i9j0k1l2",\n};\n`;
    expect(apiKeyFindings(client)).toHaveLength(1);
  });
});

describe("the supabase-js report: a demo table's open policy is information, not a live hole", () => {
  const mig = (sql: string) => supabaseMigrationFindings([{ path: "supabase/migrations/20250422000000_create_todos_table.sql", content: sql }], ref);
  const table = `CREATE TABLE IF NOT EXISTS public.todos (id int primary key, task text);\nALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;\n`;

  it("an open delete policy commented 'for backward compatibility with old tests' is one info finding", () => {
    const out = mig(`${table}-- Allow anonymous users to delete todos (for backward compatibility with old tests)\nCREATE POLICY "Allow anonymous delete access" ON public.todos FOR DELETE TO anon USING (true);\n`);
    expect(out.map((v) => v.severity)).toEqual(["info"]);
    expect(out[0]!.name).toContain("for a test or demo");
  });

  it("clean twin: the same open policy with no test or demo wording stays high", () => {
    const out = mig(`${table}-- Let anyone remove any todo\nCREATE POLICY "Allow anonymous delete access" ON public.todos FOR DELETE TO anon USING (true);\n`);
    expect(out.map((v) => v.severity)).toEqual(["high"]);
  });
});

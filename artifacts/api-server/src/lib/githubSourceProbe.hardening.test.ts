import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { parseGithubRepoRef, scanGithubRepo, isCandidatePath, githubNotScannedReason } from "./githubSourceProbe.js";
import { startGithubStub, useRealGithub, type GithubStub } from "./githubStub.testkit";

// A real server that answers like GitHub; the code under test makes real requests to it.
let gh: GithubStub;
beforeAll(async () => { gh = await startGithubStub(); });
afterAll(async () => { await gh.stop(); useRealGithub(); });
beforeEach(() => {
  gh.clear();
  process.env["GITHUB_API_URL"] = gh.api;
  process.env["GITHUB_WEB_URL"] = gh.web;
  process.env["GITHUB_RAW_URL"] = gh.raw;
});

const META = "/repos/acme/widgets";
const TREE = "/repos/acme/widgets/git/trees/main";
const publicRepo = () => gh.on("GET", "api", META, { json: { private: false, default_branch: "main" } });
const rawFiles = () => gh.requests.filter((r) => r.host === "raw").map((r) => r.path);
const REAL_SECRET = "Kq8Zr2Lm9Vb3Xt7Nc4Wd6Hs1Jp5Ae0Uo";

// ─── Hardening: reviewer scenarios, each written to fail on the first version ─────────────────

describe("parseGithubRepoRef: validation and branches", () => {
  it("honours a pasted /tree/<branch> URL instead of silently scanning the default branch", () => {
    expect(parseGithubRepoRef("https://github.com/acme/widgets/tree/release/2.0")).toEqual({ owner: "acme", repo: "widgets", branch: "release/2.0" });
    expect(parseGithubRepoRef("https://github.com/acme/widgets/tree/main")).toEqual({ owner: "acme", repo: "widgets", branch: "main" });
  });

  it("ignores other sub-pages of a repository", () => {
    expect(parseGithubRepoRef("https://github.com/acme/widgets/issues/4")).toEqual({ owner: "acme", repo: "widgets" });
  });

  it.each([
    "https://github.com/ac me/widgets",
    "https://github.com/acme/wid gets",
    "https://github.com/a%2Fb/widgets",
    "https://github.com/acme/../widgets",
  ])("rejects an owner or repo that is not a plain name: %s", (input) => {
    expect(parseGithubRepoRef(input)).toBeNull();
  });
});

describe("scanGithubRepo: the branch it was given", () => {
  it("reads the branch named in the reference, not the repository's default", async () => {
    publicRepo();
    gh.on("GET", "api", "/repos/acme/widgets/git/trees/release%2F2.0", { json: { tree: [{ path: ".env", type: "blob", size: 40 }] } });
    gh.on("GET", "raw", "/acme/widgets/release%2F2.0/.env", { text: "PORT=3000" });
    await scanGithubRepo({ owner: "acme", repo: "widgets", branch: "release/2.0" });
    expect(gh.requests.map((r) => r.path)).toContain("/repos/acme/widgets/git/trees/release%2F2.0");
    expect(rawFiles()).toEqual(["/acme/widgets/release%2F2.0/.env"]);
  });
});

describe("scanGithubRepo: an honest reason for not scanning", () => {
  const ref = { owner: "acme", repo: "widgets" };

  it("does not call a GitHub outage 'private or does not exist'", async () => {
    gh.on("GET", "api", META, { status: 503, json: {} });
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("unreachable");
    expect(githubNotScannedReason(out.status)).not.toMatch(/private|does not exist/i);
  });

  it("still calls a 404 'private or missing'", async () => {
    expect((await scanGithubRepo(ref)).status).toBe("not_public_or_missing"); // the stub has no such repository
  });

  it("calls a 403 with an exhausted quota a rate limit", async () => {
    gh.on("GET", "api", META, { status: 403, json: { message: "API rate limit exceeded" }, headers: { "x-ratelimit-remaining": "0" } });
    expect((await scanGithubRepo(ref)).status).toBe("rate_limited");
  });

  it("does not call a blocked repository a rate limit", async () => {
    gh.on("GET", "api", META, { status: 403, json: { message: "Repository access blocked" }, headers: { "x-ratelimit-remaining": "42" } });
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("blocked");
    expect(githubNotScannedReason(out.status)).not.toMatch(/rate limit/i);
  });

  it("treats a 451 as blocked", async () => {
    gh.on("GET", "api", META, { status: 451, json: { message: "Unavailable For Legal Reasons" } });
    expect((await scanGithubRepo(ref)).status).toBe("blocked");
  });

  it("says GitHub answered when the file list could not be read, rather than that it could not be reached", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { status: 404, json: { message: "Not Found" } });
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("unreadable");
    expect(githubNotScannedReason(out.status)).not.toMatch(/could not be reached/i);
  });

  it("calls a tree 5xx unreachable", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { status: 502, json: {} });
    expect((await scanGithubRepo(ref)).status).toBe("unreachable");
  });
});

describe("scanGithubRepo: reading nothing is not scanning", () => {
  const ref = { owner: "acme", repo: "widgets" };

  it("does not report 'scanned' when every candidate file failed to download", async () => {
    // filesRead 0 with candidates present: GitHub's raw host rate-limited or failed every fetch. The first version
    // returned 'scanned' and the scanner ledgered it as a clean run.
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [{ path: ".env", type: "blob", size: 40 }, { path: "config/app.json", type: "blob", size: 40 }] } });
    gh.on("GET", "raw", /^\/acme\/widgets\/main\//, { status: 429, text: "slow down" });
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("unreadable");
    expect(out.filesRead).toBe(0);
    expect(githubNotScannedReason(out.status)).toMatch(/could not be read/i);
  });

  it("still reports a repository with no candidate file as scanned (there was nothing to read)", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [{ path: "src/index.ts", type: "blob", size: 900 }] } });
    expect(await scanGithubRepo(ref)).toMatchObject({ status: "scanned", filesRead: 0 });
  });

  it("says when GitHub truncated the file list, so a partial scan does not read as a full one", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { truncated: true, tree: [{ path: ".env", type: "blob", size: 40 }] } });
    gh.on("GET", "raw", "/acme/widgets/main/.env", { text: "PORT=3000" });
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("scanned");
    expect(out.truncated).toBe(true);
    const note = out.findings.find((f) => f.category === "Scan Coverage");
    expect(note?.name).toMatch(/only part of the repository/i);
    expect(note?.evidence).toMatch(/truncated/i);
    // It must not read as a credential finding, which the check catalog matches on this suffix.
    expect(note?.name).not.toContain("(in source repository)");
  });

  it("reports the files it skipped for the cap", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: Array.from({ length: 40 }, (_, i) => ({ path: `.env.${String(i).padStart(2, "0")}`, type: "blob", size: 10 })) } });
    gh.on("GET", "raw", /^\/acme\/widgets\/main\//, { text: "PORT=3000" });
    const out = await scanGithubRepo(ref);
    expect(out.filesRead).toBe(25);
    expect(out.skipped).toBe(15);
    expect(out.findings.find((f) => f.category === "Scan Coverage")?.evidence).toMatch(/15/);
  });
});

describe("scanGithubRepo: the cap is spent on the files that matter", () => {
  it("reads the root .env and a service's .env before deep config files, however the tree is ordered", async () => {
    // Git returns paths alphabetically. Thirty files under appNN/config/ sort ahead of services/api/.env and web/.env,
    // which never reached the 25-file cap.
    const deep = Array.from({ length: 30 }, (_, i) => ({ path: `app${String(i).padStart(2, "0")}/config/settings.json`, type: "blob", size: 50 }));
    const tree = [...deep, { path: "services/api/.env", type: "blob", size: 50 }, { path: "web/.env", type: "blob", size: 50 }, { path: ".env", type: "blob", size: 50 }]
      .sort((a, b) => a.path.localeCompare(b.path));
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree } });
    gh.on("GET", "raw", /^\/acme\/widgets\/main\//, { text: "PORT=3000" });
    await scanGithubRepo({ owner: "acme", repo: "widgets" });
    const raw = rawFiles();
    expect(raw.some((u) => u.endsWith("/main/.env"))).toBe(true);
    expect(raw.some((u) => u.endsWith("/main/services/api/.env"))).toBe(true);
    expect(raw.some((u) => u.endsWith("/main/web/.env"))).toBe(true);
    expect(raw).toHaveLength(25);
  });
});

describe("scanGithubRepo: secrets in the syntaxes config files use", () => {
  it("finds an unquoted .env password, which the JS patterns cannot read", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [{ path: ".env", type: "blob", size: 80 }] } });
    gh.on("GET", "raw", "/acme/widgets/main/.env", { text: `PORT=3000\nJWT_SECRET=${REAL_SECRET}\n` });
    const out = await scanGithubRepo({ owner: "acme", repo: "widgets" });
    const f = out.findings.find((v) => /Config File/.test(v.name));
    expect(f).toBeDefined();
    expect(f!.name).toContain("(in source repository)");
    expect(f!.evidence).toContain("JWT_SECRET");
    expect(f!.evidence).toContain(".env");
    expect(f!.evidence).not.toContain(REAL_SECRET);
    expect(f!.severity).toBe("high");
  });

  it("is quiet about the same key in an .env.example holding a placeholder", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [{ path: ".env.example", type: "blob", size: 80 }] } });
    gh.on("GET", "raw", "/acme/widgets/main/.env.example", {
      text: "JWT_SECRET=your-secret-here\nDATABASE_URL=postgres://postgres:postgres@localhost:5432/mydb\nSTRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxx\n",
    });
    expect((await scanGithubRepo({ owner: "acme", repo: "widgets" })).findings).toEqual([]);
  });
});

describe("scanGithubRepo: bounded in time as well as in requests", () => {
  it("gives up on a response body that never arrives", async () => {
    // The timer used to be cleared as soon as headers arrived; .json() and .text() then ran untimed. The server here
    // sends the headers and the start of a body, then never finishes.
    gh.on("GET", "api", META, { stallBody: true });
    const started = Date.now();
    const out = await scanGithubRepo({ owner: "acme", repo: "widgets" }, { timeoutMs: 300 });
    expect(out.status).toBe("unreachable");
    expect(Date.now() - started).toBeLessThan(3_000);
  });
});

describe("isCandidatePath", () => {
  it.each([
    ".env", ".env.production", ".env.production.local", ".env.development.local", ".env.test.local", ".env.example",
    "apps/api/.env", ".envrc", ".npmrc", ".netrc", "terraform.tfvars", "infra/prod.tfvars", "config/master.key",
    "firebase-adminsdk-abc12.json", "local_settings.py", "app/settings.py", "docker-compose.yml", "docker-compose.prod.yml",
    "docker-compose.override.yaml", "compose.yaml", "wp-config.php", "appsettings.Production.json", "config/database.yml",
    "app/config/secrets.json", "serviceAccountKey.json", "supabase/migrations/20240101_init.sql", ".aws/credentials",
  ])("reads %s", (path) => {
    expect(isCandidatePath(path)).toBe(true);
  });

  it.each([
    "src/config/index.ts", "config/webpack.config.js", "src/config/routes.js", "node_modules/pkg/config/defaults.json",
    "vendor/lib/config/x.yml", "test/fixtures/.env", "tests/.env.test", "__tests__/config/settings.json",
    "notsupabase/migrations/x.sql", "docs/config/README.md", "src/index.ts", "package.json",
  ])("skips %s", (path) => {
    expect(isCandidatePath(path)).toBe(false);
  });
});

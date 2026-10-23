import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { parseGithubRepoRef, scanGithubRepoForSecrets, scanGithubRepo } from "./githubSourceProbe.js";
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

const REPO = { owner: "acme", repo: "widgets" };
const META = "/repos/acme/widgets";
const TREE = "/repos/acme/widgets/git/trees/main";
/** A public repository whose default branch is main. */
const publicRepo = () => gh.on("GET", "api", META, { json: { private: false, default_branch: "main" } });

describe("parseGithubRepoRef", () => {
  it("parses a bare owner/repo", () => {
    expect(parseGithubRepoRef("acme/widgets")).toEqual({ owner: "acme", repo: "widgets" });
  });
  it("parses a full github.com URL, stripping .git", () => {
    expect(parseGithubRepoRef("https://github.com/acme/widgets.git")).toEqual({ owner: "acme", repo: "widgets" });
  });
  it("rejects a non-GitHub URL", () => {
    expect(parseGithubRepoRef("https://gitlab.com/acme/widgets")).toBeNull();
  });
  it("rejects dot names in the bare form as it does in the URL form", () => {
    for (const v of ["../..", "./.", "acme/..", "../shop", ".git/.git", "acme/.git", "https://github.com/acme/.git"]) {
      expect(parseGithubRepoRef(v), v).toBeNull();
    }
  });
  it("rejects nonsense input", () => {
    expect(parseGithubRepoRef("not a repo at all")).toBeNull();
  });
});

describe("scanGithubRepoForSecrets", () => {
  it("returns nothing for a private repository, and never attempts to read one", async () => {
    gh.on("GET", "api", META, { json: { private: true, default_branch: "main" } });
    expect(await scanGithubRepoForSecrets(REPO)).toEqual([]);
    // Only the metadata call was made: no tree or file fetch for a private repo.
    expect(gh.requests).toHaveLength(1);
  });

  it("returns nothing when the repo metadata call fails (404, rate-limited, network error)", async () => {
    expect(await scanGithubRepoForSecrets({ owner: "acme", repo: "ghost" })).toEqual([]); // the stub has no such repository: 404
  });

  it("finds a real secret pattern in a candidate file from a public repo", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [
      { path: ".env", type: "blob", size: 200 },
      { path: "src/index.ts", type: "blob", size: 5000 }, // not a candidate path
    ] } });
    gh.on("GET", "raw", "/acme/widgets/main/.env", { text: "STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc" });

    const findings = await scanGithubRepoForSecrets(REPO);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.category).toBe("Exposed Secrets / Credentials");
    expect(findings[0]!.name).toMatch(/in source repository/i);
    // The raw secret must never appear in the evidence.
    expect(findings[0]!.evidence).not.toContain("sk_live_4eC39HqLyjWDarjtT1zdp7dc");
    // Only the candidate file was fetched.
    expect(gh.requests.filter((r) => r.host === "raw").map((r) => r.path)).toEqual(["/acme/widgets/main/.env"]);
  });

  it("describes a repository finding as a repository finding, not a script shipped to a browser", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [{ path: ".env", type: "blob", size: 200 }] } });
    gh.on("GET", "raw", "/acme/widgets/main/.env", { text: "DATABASE_URL=postgres://appuser:Zx7Qm2vLp9Rt4Wk8@db.fixture.invalid:5432/orders" });

    const [f] = await scanGithubRepoForSecrets(REPO);
    expect(f!.description).toContain("acme/widgets");
    expect(f!.description).toContain(".env");
    // The pattern's own text is about a secret in client-side JavaScript that "anyone who views your page" can read.
    expect(f!.description).not.toMatch(/client-side|views your page|JavaScript/i);
    expect(f!.solution).toMatch(/^Rotate the credential now/);
    expect(f!.evidence).not.toContain("Zx7Qm2vLp9Rt4Wk8");
  });

  it("encodes each path segment, so a file in a directory named with # or ? is still fetched", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [{ path: "a#b/.env", type: "blob", size: 50 }] } });
    gh.on("GET", "raw", /^\/acme\/widgets\/main\//, { text: "X=1" });
    await scanGithubRepoForSecrets(REPO);
    const raw = gh.requests.filter((r) => r.host === "raw");
    expect(raw).toHaveLength(1);
    expect(raw[0]!.path).toBe("/acme/widgets/main/a%23b/.env");
  });

  it("never sends an Authorization header (public repos only, no token)", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [] } });
    await scanGithubRepoForSecrets(REPO);
    expect(gh.requests.length).toBeGreaterThan(0);
    for (const r of gh.requests) expect(r.headers["authorization"]).toBeUndefined();
  });

  it("bounds the number of files fetched", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: Array.from({ length: 50 }, (_, i) => ({ path: `.env.${i}`, type: "blob", size: 100 })) } });
    gh.on("GET", "raw", /^\/acme\/widgets\/main\//, { text: "nothing interesting here" });
    await scanGithubRepoForSecrets(REPO);
    // 2 metadata/tree calls + at most 25 file fetches.
    expect(gh.requests.length).toBeLessThanOrEqual(27);
  });
});

describe("scanGithubRepo: says why a repository was not looked at", () => {
  it("reports a private repository as not public", async () => {
    gh.on("GET", "api", META, { json: { private: true, default_branch: "main" } });
    expect((await scanGithubRepo(REPO)).status).toBe("not_public_or_missing");
  });

  it("reports a rate-limited answer as such, not as a missing repository", async () => {
    gh.on("GET", "api", META, { status: 403, json: {} });
    expect((await scanGithubRepo(REPO)).status).toBe("rate_limited");
  });

  it("reports a network fault as unreachable", async () => {
    // Nothing listens on port 1: the connection is genuinely refused.
    process.env["GITHUB_API_URL"] = "http://127.0.0.1:1";
    expect((await scanGithubRepo(REPO)).status).toBe("unreachable");
  });

  it("reports a repository with no commits as empty", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { status: 409, json: {} });
    expect((await scanGithubRepo(REPO)).status).toBe("empty");
  });

  it("counts the files it read when it does scan", async () => {
    publicRepo();
    gh.on("GET", "api", TREE, { json: { tree: [{ path: ".env.example", type: "blob", size: 40 }] } });
    gh.on("GET", "raw", "/acme/widgets/main/.env.example", { text: `DEEPSEEK_API_KEY="MY_DEEPSEEK_API_KEY"` });
    expect(await scanGithubRepo(REPO)).toMatchObject({ status: "scanned", filesRead: 1, findings: [] });
  });
});

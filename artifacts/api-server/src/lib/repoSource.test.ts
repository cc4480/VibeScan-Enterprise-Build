import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from "vitest";
import { publicGithubSource, publicApiHeaders } from "./repoSource";
import { startGithubStub, useRealGithub, type GithubStub } from "./githubStub.testkit";

const ref = { owner: "acme", repo: "big" };

// A real server that answers like GitHub; the code under test makes real requests to it.
let gh: GithubStub;
const savedToken = process.env["GITHUB_PUBLIC_API_TOKEN"];
beforeAll(async () => { gh = await startGithubStub(); });
afterAll(async () => { await gh.stop(); useRealGithub(); });
beforeEach(() => {
  gh.clear();
  process.env["GITHUB_API_URL"] = gh.api;
  process.env["GITHUB_WEB_URL"] = gh.web;
  process.env["GITHUB_RAW_URL"] = gh.raw;
  delete process.env["GITHUB_PUBLIC_API_TOKEN"];
});
afterEach(() => {
  if (savedToken === undefined) delete process.env["GITHUB_PUBLIC_API_TOKEN"];
  else process.env["GITHUB_PUBLIC_API_TOKEN"] = savedToken;
});

const META = "/repos/acme/big";
const tree = (name: string) => `/repos/acme/big/git/trees/${name}`;

describe("opening a repository whose file list GitHub cut off", () => {
  it("walks it folder by folder, so its size does not decide which files are seen", async () => {
    gh.on("GET", "api", META, { json: { private: false, default_branch: "main" } });
    gh.on("GET", "api", tree("main"), { json: { sha: "root", truncated: true, tree: [{ path: "a.txt", type: "blob", size: 1 }] } });
    gh.on("GET", "api", tree("root"), { json: { tree: [{ path: "a.txt", type: "blob", size: 1 }, { path: "src", type: "tree", sha: "src1" }, { path: "sub", type: "commit", sha: "x" }] } });
    gh.on("GET", "api", tree("src1"), { json: { tree: [{ path: "index.ts", type: "blob", size: 5 }, { path: "deep", type: "tree", sha: "deep1" }] } });
    gh.on("GET", "api", tree("deep1"), { json: { tree: [{ path: "last.ts", type: "blob", size: 7 }] } });
    const opened = await publicGithubSource(ref).open();
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(opened.tree.map((f) => f.path).sort()).toEqual(["a.txt", "src/deep/last.ts", "src/index.ts"]);
    expect(opened.truncated).toBe(false);
  });

  it("still says the list is partial when a folder cannot be listed", async () => {
    gh.on("GET", "api", META, { json: { private: false, default_branch: "main" } });
    gh.on("GET", "api", tree("main"), { json: { sha: "root", truncated: true, tree: [{ path: "a.txt", type: "blob", size: 1 }] } });
    gh.on("GET", "api", tree("root"), { json: { tree: [{ path: "a.txt", type: "blob", size: 1 }, { path: "src", type: "tree", sha: "missing" }] } });
    // tree("missing") is not served: GitHub answers 404 for it.
    const opened = await publicGithubSource(ref).open();
    expect(opened.ok && opened.truncated).toBe(true);
  });
});

describe("the optional token for reading public repositories", () => {
  it("is sent to the API and never to the file host", async () => {
    process.env["GITHUB_PUBLIC_API_TOKEN"] = "  github_pat_test_value  ";
    gh.on("GET", "api", META, { json: { private: false, default_branch: "main" } });
    gh.on("GET", "api", tree("main"), { json: { tree: [{ path: "a.txt", type: "blob", size: 1 }] } });
    gh.on("GET", "raw", "/acme/big/main/a.txt", { text: "hello" });
    const source = publicGithubSource(ref);
    const opened = await source.open();
    expect(opened.ok).toBe(true);
    if (opened.ok) await source.read("a.txt", opened.branch);
    const api = gh.requests.filter((r) => r.host === "api");
    const raw = gh.requests.filter((r) => r.host === "raw");
    expect(api.length).toBeGreaterThan(0);
    expect(api.every((r) => r.headers["authorization"] === "Bearer github_pat_test_value")).toBe(true);
    expect(raw).toHaveLength(1);
    expect(raw[0]!.headers["authorization"]).toBeUndefined();
  });

  it("is absent when not configured, so nothing changes for a deployment without one", () => {
    expect(publicApiHeaders({})).toEqual({});
    expect(publicApiHeaders({ GITHUB_PUBLIC_API_TOKEN: "   " })).toEqual({});
  });

  it("still refuses a private repository, whatever the token could see", async () => {
    process.env["GITHUB_PUBLIC_API_TOKEN"] = "github_pat_test_value";
    gh.on("GET", "api", META, { json: { private: true, default_branch: "main" } });
    const opened = await publicGithubSource(ref).open();
    expect(opened).toMatchObject({ ok: false, status: "not_public_or_missing" });
  });
});

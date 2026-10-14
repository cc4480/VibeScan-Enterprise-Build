import { describe, it, expect, vi, afterEach } from "vitest";
import { publicGithubSource, publicApiHeaders } from "./repoSource";

const ref = { owner: "acme", repo: "big" };

/** A fake GitHub: answers each URL from a table, and records the calls. */
function fakeGithub(routes: Record<string, unknown>) {
  const calls: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    calls.push(url);
    const key = Object.keys(routes).find((k) => url.endsWith(k));
    if (!key) return new Response("{}", { status: 404 });
    return new Response(JSON.stringify(routes[key]), { status: 200, headers: { "content-type": "application/json" } });
  }));
  return calls;
}

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

describe("opening a repository whose file list GitHub cut off", () => {
  it("walks it folder by folder, so its size does not decide which files are seen", async () => {
    fakeGithub({
      "/repos/acme/big": { private: false, default_branch: "main" },
      "/git/trees/main?recursive=1": { sha: "root", truncated: true, tree: [{ path: "a.txt", type: "blob", size: 1 }] },
      "/git/trees/root": { tree: [{ path: "a.txt", type: "blob", size: 1 }, { path: "src", type: "tree", sha: "src1" }, { path: "sub", type: "commit", sha: "x" }] },
      "/git/trees/src1": { tree: [{ path: "index.ts", type: "blob", size: 5 }, { path: "deep", type: "tree", sha: "deep1" }] },
      "/git/trees/deep1": { tree: [{ path: "last.ts", type: "blob", size: 7 }] },
    });
    const opened = await publicGithubSource(ref).open();
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(opened.tree.map((f) => f.path).sort()).toEqual(["a.txt", "src/deep/last.ts", "src/index.ts"]);
    expect(opened.truncated).toBe(false);
  });

  it("still says the list is partial when a folder cannot be listed", async () => {
    fakeGithub({
      "/repos/acme/big": { private: false, default_branch: "main" },
      "/git/trees/main?recursive=1": { sha: "root", truncated: true, tree: [{ path: "a.txt", type: "blob", size: 1 }] },
      "/git/trees/root": { tree: [{ path: "a.txt", type: "blob", size: 1 }, { path: "src", type: "tree", sha: "missing" }] },
    });
    const opened = await publicGithubSource(ref).open();
    expect(opened.ok && opened.truncated).toBe(true);
  });
});

describe("the optional token for reading public repositories", () => {
  it("is sent to the API and never to the file host", async () => {
    const seen: Array<{ url: string; auth: string | undefined }> = [];
    vi.stubEnv("GITHUB_PUBLIC_API_TOKEN", "  github_pat_test_value  ");
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: { headers?: Record<string, string> }) => {
      seen.push({ url, auth: init?.headers?.["Authorization"] });
      if (url.endsWith("/repos/acme/big")) return new Response(JSON.stringify({ private: false, default_branch: "main" }), { status: 200 });
      if (url.includes("/git/trees/")) return new Response(JSON.stringify({ tree: [{ path: "a.txt", type: "blob", size: 1 }] }), { status: 200 });
      return new Response("hello", { status: 200 });
    }));
    const source = publicGithubSource(ref);
    const opened = await source.open();
    expect(opened.ok).toBe(true);
    if (opened.ok) await source.read("a.txt", opened.branch);
    const api = seen.filter((c) => c.url.startsWith("https://api.github.com/"));
    const raw = seen.filter((c) => c.url.startsWith("https://raw.githubusercontent.com/"));
    expect(api.length).toBeGreaterThan(0);
    expect(api.every((c) => c.auth === "Bearer github_pat_test_value")).toBe(true);
    expect(raw.length).toBe(1);
    expect(raw[0]!.auth).toBeUndefined();
  });

  it("is absent when not configured, so nothing changes for a deployment without one", () => {
    expect(publicApiHeaders({})).toEqual({});
    expect(publicApiHeaders({ GITHUB_PUBLIC_API_TOKEN: "   " })).toEqual({});
  });

  it("still refuses a private repository, whatever the token could see", async () => {
    vi.stubEnv("GITHUB_PUBLIC_API_TOKEN", "github_pat_test_value");
    fakeGithub({ "/repos/acme/big": { private: true, default_branch: "main" } });
    const opened = await publicGithubSource(ref).open();
    expect(opened).toMatchObject({ ok: false, status: "not_public_or_missing" });
  });
});

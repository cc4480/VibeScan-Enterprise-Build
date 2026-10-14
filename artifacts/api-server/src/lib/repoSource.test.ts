import { describe, it, expect, vi, afterEach } from "vitest";
import { publicGithubSource } from "./repoSource";

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

afterEach(() => vi.unstubAllGlobals());

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

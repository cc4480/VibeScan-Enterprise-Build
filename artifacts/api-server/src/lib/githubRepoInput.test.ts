import { describe, it, expect } from "vitest";
import { normaliseGithubRepoInput } from "./githubRepoInput";
import { parseGithubRepoRef } from "./githubSourceProbe";

describe("normaliseGithubRepoInput", () => {
  it("treats empty, blank and missing input as no source scan", () => {
    for (const v of [undefined, null, "", "   "]) expect(normaliseGithubRepoInput(v)).toEqual({ ok: true, url: null });
  });

  it("normalises the accepted spellings to one URL", () => {
    for (const v of ["acme/shop", "https://github.com/acme/shop", "https://github.com/acme/shop.git", "  https://www.github.com/acme/shop/  "]) {
      expect(normaliseGithubRepoInput(v)).toEqual({ ok: true, url: "https://github.com/acme/shop" });
    }
  });

  it("keeps a named branch, and the result parses back to the same repository", () => {
    const r = normaliseGithubRepoInput("https://github.com/acme/shop/tree/release/2026");
    expect(r).toEqual({ ok: true, url: "https://github.com/acme/shop/tree/release/2026" });
    expect(parseGithubRepoRef((r as { url: string }).url)).toEqual({ owner: "acme", repo: "shop", branch: "release/2026" });
  });

  it("rejects other hosts, private-looking paths, traversal and oversized input", () => {
    for (const v of [
      "https://gitlab.com/acme/shop",
      "https://github.com.evil.example/acme/shop",
      "https://github.com/acme",
      "https://github.com/acme/..",
      "http://127.0.0.1/acme/shop",
      "not a repo",
      "acme/shop/extra",
      "../..",
      ".git/.git",
      "a/".repeat(200),
    ]) {
      expect(normaliseGithubRepoInput(v).ok, v).toBe(false);
    }
  });
});

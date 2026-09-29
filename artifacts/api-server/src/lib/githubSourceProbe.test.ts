import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseGithubRepoRef, scanGithubRepoForSecrets, scanGithubRepo } from "./githubSourceProbe.js";

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});
afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonRes(body: unknown, ok = true): Response {
  return new Response(JSON.stringify(body), { status: ok ? 200 : 404 });
}
function textRes(body: string, ok = true): Response {
  return new Response(body, { status: ok ? 200 : 404 });
}

describe("parseGithubRepoRef", () => {
  it("parses a bare owner/repo", () => {
    expect(parseGithubRepoRef("acme/widgets")).toEqual({ owner: "acme", repo: "widgets" });
  });
  it("parses a full github.com URL, stripping .git", () => {
    expect(parseGithubRepoRef("https://github.com/acme/widgets.git")).toEqual({
      owner: "acme",
      repo: "widgets",
    });
  });
  it("rejects a non-GitHub URL", () => {
    expect(parseGithubRepoRef("https://gitlab.com/acme/widgets")).toBeNull();
  });
  it("rejects nonsense input", () => {
    expect(parseGithubRepoRef("not a repo at all")).toBeNull();
  });
});

describe("scanGithubRepoForSecrets", () => {
  it("returns nothing for a private repository — never attempts to read one", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonRes({ private: true, default_branch: "main" }));
    const findings = await scanGithubRepoForSecrets({ owner: "acme", repo: "widgets" });
    expect(findings).toEqual([]);
    // Only the metadata call was made — no tree or file fetch for a private repo.
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("returns nothing when the repo metadata call fails (404, rate-limited, network error)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonRes({}, false));
    const findings = await scanGithubRepoForSecrets({ owner: "acme", repo: "ghost" });
    expect(findings).toEqual([]);
  });

  it("finds a real secret pattern in a candidate file from a public repo", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" })) // repo meta
      .mockResolvedValueOnce(
        jsonRes({
          tree: [
            { path: ".env", type: "blob", size: 200 },
            { path: "src/index.ts", type: "blob", size: 5000 }, // not a candidate path
          ],
        }),
      ) // tree
      .mockResolvedValueOnce(textRes("STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc"));

    const findings = await scanGithubRepoForSecrets({ owner: "acme", repo: "widgets" });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.category).toBe("Exposed Secrets / Credentials");
    expect(findings[0]!.name).toMatch(/in source repository/i);
    // The raw secret must never appear in the evidence.
    expect(findings[0]!.evidence).not.toContain("sk_live_4eC39HqLyjWDarjtT1zdp7dc");
  });

  it("never sends an Authorization header (public repos only, no token)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }));
    vi.mocked(fetch).mockResolvedValueOnce(jsonRes({ tree: [] }));
    await scanGithubRepoForSecrets({ owner: "acme", repo: "widgets" });
    for (const call of vi.mocked(fetch).mock.calls) {
      const init = call[1] as RequestInit | undefined;
      const headers = new Headers(init?.headers);
      expect(headers.has("authorization")).toBe(false);
    }
  });

  it("bounds the number of files fetched", async () => {
    const manyFiles = Array.from({ length: 50 }, (_, i) => ({
      path: `.env.${i}`,
      type: "blob",
      size: 100,
    }));
    vi.mocked(fetch).mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }));
    vi.mocked(fetch).mockResolvedValueOnce(jsonRes({ tree: manyFiles }));
    vi.mocked(fetch).mockResolvedValue(textRes("nothing interesting here"));

    await scanGithubRepoForSecrets({ owner: "acme", repo: "widgets" });
    // 2 metadata/tree calls + at most 25 file fetches.
    expect(vi.mocked(fetch).mock.calls.length).toBeLessThanOrEqual(27);
  });
});

describe("scanGithubRepo — says why a repository was not looked at", () => {
  it("reports a private repository as not public", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonRes({ private: true, default_branch: "main" }));
    expect((await scanGithubRepo({ owner: "acme", repo: "widgets" })).status).toBe("not_public_or_missing");
  });

  it("reports a rate-limited answer as such, not as a missing repository", async () => {
    vi.mocked(fetch).mockResolvedValueOnce({ ok: false, status: 403, json: async () => ({}), text: async () => "" } as unknown as Response);
    expect((await scanGithubRepo({ owner: "acme", repo: "widgets" })).status).toBe("rate_limited");
  });

  it("reports a network fault as unreachable", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error("offline"));
    expect((await scanGithubRepo({ owner: "acme", repo: "widgets" })).status).toBe("unreachable");
  });

  it("reports a repository with no commits as empty", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce({ ok: false, status: 409, json: async () => ({}), text: async () => "" } as unknown as Response);
    expect((await scanGithubRepo({ owner: "acme", repo: "widgets" })).status).toBe("empty");
  });

  it("counts the files it read when it does scan", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ tree: [{ path: ".env.example", type: "blob", size: 40 }] }))
      .mockResolvedValueOnce(textRes(`DEEPSEEK_API_KEY="MY_DEEPSEEK_API_KEY"`));
    const out = await scanGithubRepo({ owner: "acme", repo: "widgets" });
    expect(out).toMatchObject({ status: "scanned", filesRead: 1, findings: [] });
  });
});

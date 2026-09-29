import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parseGithubRepoRef, scanGithubRepo } from "./githubSourceProbe.js";

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

// ─── Hardening: reviewer scenarios, each written to fail on the first version ─────────────────

import { isCandidatePath, githubNotScannedReason } from "./githubSourceProbe.js";

const REAL_SECRET = "Kq8Zr2Lm9Vb3Xt7Nc4Wd6Hs1Jp5Ae0Uo";

function statusRes(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers });
}
const urlsFetched = (): string[] => vi.mocked(fetch).mock.calls.map((c) => String(c[0]));

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
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ tree: [{ path: ".env", type: "blob", size: 40 }] }))
      .mockResolvedValueOnce(textRes("PORT=3000"));
    await scanGithubRepo({ owner: "acme", repo: "widgets", branch: "release/2.0" });
    const urls = urlsFetched();
    expect(urls[1]).toContain("/git/trees/release%2F2.0");
    expect(urls[2]).toContain("/release%2F2.0/.env");
  });
});

describe("scanGithubRepo: an honest reason for not scanning", () => {
  const ref = { owner: "acme", repo: "widgets" };

  it("does not call a GitHub outage 'private or does not exist'", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(statusRes(503));
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("unreachable");
    expect(githubNotScannedReason(out.status)).not.toMatch(/private|does not exist/i);
  });

  it("still calls a 404 'private or missing'", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(statusRes(404));
    expect((await scanGithubRepo(ref)).status).toBe("not_public_or_missing");
  });

  it("calls a 403 with an exhausted quota a rate limit", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(statusRes(403, { message: "API rate limit exceeded" }, { "x-ratelimit-remaining": "0" }));
    expect((await scanGithubRepo(ref)).status).toBe("rate_limited");
  });

  it("does not call a blocked repository a rate limit", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(statusRes(403, { message: "Repository access blocked" }, { "x-ratelimit-remaining": "42" }));
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("blocked");
    expect(githubNotScannedReason(out.status)).not.toMatch(/rate limit/i);
  });

  it("treats a 451 as blocked", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(statusRes(451, { message: "Unavailable For Legal Reasons" }));
    expect((await scanGithubRepo(ref)).status).toBe("blocked");
  });

  it("says GitHub answered when the file list could not be read, rather than that it could not be reached", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(statusRes(404, { message: "Not Found" }));
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("unreadable");
    expect(githubNotScannedReason(out.status)).not.toMatch(/could not be reached/i);
  });

  it("calls a tree 5xx unreachable", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(statusRes(502));
    expect((await scanGithubRepo(ref)).status).toBe("unreachable");
  });
});

describe("scanGithubRepo: reading nothing is not scanning", () => {
  const ref = { owner: "acme", repo: "widgets" };

  it("does not report 'scanned' when every candidate file failed to download", async () => {
    // filesRead 0 with candidates present: GitHub's raw host rate-limited or failed every fetch. The
    // first version returned 'scanned' and the scanner ledgered it as a clean run.
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ tree: [{ path: ".env", type: "blob", size: 40 }, { path: "config/app.json", type: "blob", size: 40 }] }))
      .mockImplementation(async () => statusRes(429, "slow down"));
    const out = await scanGithubRepo(ref);
    expect(out.status).toBe("unreadable");
    expect(out.filesRead).toBe(0);
    expect(githubNotScannedReason(out.status)).toMatch(/could not be read/i);
  });

  it("still reports a repository with no candidate file as scanned (there was nothing to read)", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ tree: [{ path: "src/index.ts", type: "blob", size: 900 }] }));
    expect(await scanGithubRepo(ref)).toMatchObject({ status: "scanned", filesRead: 0 });
  });

  it("says when GitHub truncated the file list, so a partial scan does not read as a full one", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ truncated: true, tree: [{ path: ".env", type: "blob", size: 40 }] }))
      .mockResolvedValueOnce(textRes("PORT=3000"));
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
    const many = Array.from({ length: 40 }, (_, i) => ({ path: `.env.${String(i).padStart(2, "0")}`, type: "blob", size: 10 }));
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ tree: many }))
      .mockImplementation(async () => textRes("PORT=3000"));
    const out = await scanGithubRepo(ref);
    expect(out.filesRead).toBe(25);
    expect(out.skipped).toBe(15);
    expect(out.findings.find((f) => f.category === "Scan Coverage")?.evidence).toMatch(/15/);
  });
});

describe("scanGithubRepo: the cap is spent on the files that matter", () => {
  it("reads the root .env and a service's .env before deep config files, however the tree is ordered", async () => {
    // Git returns paths alphabetically. Thirty files under appNN/config/ sort ahead of services/api/.env
    // and web/.env, which never reached the 25-file cap.
    const deep = Array.from({ length: 30 }, (_, i) => ({ path: `app${String(i).padStart(2, "0")}/config/settings.json`, type: "blob", size: 50 }));
    const tree = [...deep, { path: "services/api/.env", type: "blob", size: 50 }, { path: "web/.env", type: "blob", size: 50 }, { path: ".env", type: "blob", size: 50 }]
      .sort((a, b) => a.path.localeCompare(b.path));
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ tree }))
      .mockImplementation(async () => textRes("PORT=3000"));
    await scanGithubRepo({ owner: "acme", repo: "widgets" });
    const raw = urlsFetched().slice(2);
    expect(raw.some((u) => u.endsWith("/main/.env"))).toBe(true);
    expect(raw.some((u) => u.endsWith("/main/services/api/.env"))).toBe(true);
    expect(raw.some((u) => u.endsWith("/main/web/.env"))).toBe(true);
    expect(raw.length).toBe(25);
  });
});

describe("scanGithubRepo: secrets in the syntaxes config files use", () => {
  it("finds an unquoted .env password, which the JS patterns cannot read", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ tree: [{ path: ".env", type: "blob", size: 80 }] }))
      .mockResolvedValueOnce(textRes(`PORT=3000\nJWT_SECRET=${REAL_SECRET}\n`));
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
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonRes({ private: false, default_branch: "main" }))
      .mockResolvedValueOnce(jsonRes({ tree: [{ path: ".env.example", type: "blob", size: 80 }] }))
      .mockResolvedValueOnce(textRes("JWT_SECRET=your-secret-here\nDATABASE_URL=postgres://postgres:postgres@localhost:5432/mydb\nSTRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxx\n"));
    const out = await scanGithubRepo({ owner: "acme", repo: "widgets" });
    expect(out.findings).toEqual([]);
  });
});

describe("scanGithubRepo: bounded in time as well as in requests", () => {
  it("gives up on a response body that never arrives", async () => {
    // The timer used to be cleared as soon as headers arrived; .json() and .text() then ran untimed.
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true, status: 200, headers: new Headers(),
      json: () => new Promise(() => {}), text: () => new Promise(() => {}),
    } as unknown as Response);
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

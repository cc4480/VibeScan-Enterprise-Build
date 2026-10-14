import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import {
  GithubConnectError,
  authorizeUrl,
  connectConfigured,
  exchangeCode,
  githubClientConfig,
  installationRepositories,
  installationRepositoryList,
  userInstallations,
} from "./githubConnect";
import { installationForRepo } from "./githubInstallationAccess";

// A throwaway key made for the test; nothing here is a GitHub credential.
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const cfg = { appId: "4242", privateKey, slug: "test-app" };
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

describe("configuration", () => {
  it("needs both the client id and the client secret", () => {
    expect(githubClientConfig({ GITHUB_APP_CLIENT_ID: "x" })).toBeNull();
    expect(githubClientConfig({ GITHUB_APP_CLIENT_ID: "x", GITHUB_APP_CLIENT_SECRET: "y" })).toEqual({ clientId: "x", clientSecret: "y" });
  });

  it("is ready only with the App (and its slug) and the OAuth client", () => {
    const base = { GITHUB_APP_ID: "1", GITHUB_APP_PRIVATE_KEY: privateKey, GITHUB_APP_CLIENT_ID: "x", GITHUB_APP_CLIENT_SECRET: "y" };
    expect(connectConfigured(base)).toBe(false);
    expect(connectConfigured({ ...base, GITHUB_APP_SLUG: "s" })).toBe(true);
  });

  it("builds the authorise link with the state", () => {
    expect(authorizeUrl({ clientId: "Iv1.a", clientSecret: "s" }, "st ate")).toBe("https://github.com/login/oauth/authorize?client_id=Iv1.a&state=st%20ate");
  });
});

describe("exchangeCode", () => {
  const client = { clientId: "id", clientSecret: "secret" };

  it("returns the user token GitHub gives for the code", async () => {
    expect(await exchangeCode("c", client, vi.fn(async () => json(200, { access_token: "tok" })) as unknown as typeof fetch)).toBe("tok");
  });

  it("treats GitHub's 200-with-an-error answer as a rejected code", async () => {
    await expect(exchangeCode("c", client, vi.fn(async () => json(200, { error: "bad_verification_code" })) as unknown as typeof fetch))
      .rejects.toMatchObject({ reason: "code_rejected" });
  });

  it("calls GitHub being unreachable what it is", async () => {
    const down = vi.fn(async () => { throw new Error("net"); }) as unknown as typeof fetch;
    await expect(exchangeCode("c", client, down)).rejects.toBeInstanceOf(GithubConnectError);
  });
});

describe("userInstallations", () => {
  it("keeps only this App's installations, with their account names", async () => {
    const fetchFn = vi.fn(async () => json(200, { installations: [
      { id: 1, app_id: 4242, account: { login: "me" } },
      { id: 2, app_id: 7, account: { login: "someone-else" } },
      { id: 3, app_id: "4242", account: null },
    ] })) as unknown as typeof fetch;
    expect(await userInstallations("t", "4242", fetchFn)).toEqual([
      { installationId: 1, accountLogin: "me" },
      { installationId: 3, accountLogin: null },
    ]);
  });

  it("throws when GitHub refuses, so nothing is recorded", async () => {
    await expect(userInstallations("t", "4242", vi.fn(async () => json(401, {})) as unknown as typeof fetch)).rejects.toBeInstanceOf(GithubConnectError);
  });
});

describe("installationRepositories", () => {
  it("lists what the installation can read", async () => {
    const fetchFn = vi.fn(async (url: string | URL | Request) =>
      String(url).includes("/access_tokens")
        ? json(201, { token: "inst" })
        : json(200, { repositories: [{ full_name: "me/app", private: true, html_url: "https://github.com/me/app" }] })) as unknown as typeof fetch;
    expect(await installationRepositories(5, cfg, fetchFn)).toEqual([{ fullName: "me/app", private: true, url: "https://github.com/me/app", installationId: 5 }]);
  });

  it("is empty, not an error, when the installation is gone", async () => {
    expect(await installationRepositories(5, cfg, vi.fn(async () => json(404, {})) as unknown as typeof fetch)).toEqual([]);
    expect(await installationRepositories(5, null)).toEqual([]);
  });
});

describe("authorizeUrl", () => {
  it("names the address GitHub must return to, when given one", () => {
    const url = new URL(authorizeUrl({ clientId: "Iv1.x", clientSecret: "s" }, "st", "https://secscan.us/api/github/callback"));
    expect(url.searchParams.get("redirect_uri")).toBe("https://secscan.us/api/github/callback");
    expect(new URL(authorizeUrl({ clientId: "Iv1.x", clientSecret: "s" }, "st")).searchParams.has("redirect_uri")).toBe(false);
  });
});

describe("reading every page of what GitHub lists", () => {
  const page = (n: number, start: number) => ({ installations: Array.from({ length: n }, (_, i) => ({ id: start + i, app_id: 4242, account: { login: `a${start + i}` } })) });

  it("follows installations onto a second page", async () => {
    const urls: string[] = [];
    const fetchFn = vi.fn(async (url: string | URL | Request) => {
      urls.push(String(url));
      return json(200, String(url).includes("&page=1") ? page(100, 1) : page(3, 101));
    });
    const got = await userInstallations("t", "4242", fetchFn as unknown as typeof fetch);
    expect(got).toHaveLength(103);
    expect(urls).toHaveLength(2);
  });

  it("stops after one page when it was not full", async () => {
    const fetchFn = vi.fn(async () => json(200, page(2, 1)));
    await userInstallations("t", "4242", fetchFn as unknown as typeof fetch);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("does not loop forever on a list that never ends", async () => {
    const fetchFn = vi.fn(async () => json(200, page(100, 1)));
    await userInstallations("t", "4242", fetchFn as unknown as typeof fetch);
    expect(fetchFn.mock.calls.length).toBeLessThanOrEqual(10);
  });

  it("lists more than 100 repositories", async () => {
    const repos = (n: number, start: number) => ({ repositories: Array.from({ length: n }, (_, i) => ({ full_name: `me/r${start + i}`, html_url: `https://github.com/me/r${start + i}`, private: true })) });
    const fetchFn = vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      if (u.includes("access_tokens")) return json(201, { token: "tok" });
      return json(200, u.includes("&page=1") ? repos(100, 0) : repos(40, 100));
    });
    const r = await installationRepositoryList(5, cfg, fetchFn as unknown as typeof fetch);
    expect(r.status).toBe("ok");
    expect(r.repositories).toHaveLength(140);
  });
});

describe("how a connection stands", () => {
  it("is gone when GitHub says the installation no longer exists (the App was uninstalled)", async () => {
    expect((await installationRepositoryList(5, cfg, vi.fn(async () => json(404, {})) as unknown as typeof fetch)).status).toBe("gone");
  });

  it("is unavailable, not gone, when GitHub cannot be asked", async () => {
    expect((await installationRepositoryList(5, cfg, vi.fn(async () => json(502, {})) as unknown as typeof fetch)).status).toBe("unavailable");
    expect((await installationRepositoryList(5, cfg, vi.fn(async () => { throw new Error("down"); }) as unknown as typeof fetch)).status).toBe("unavailable");
    expect((await installationRepositoryList(5, null)).status).toBe("unavailable");
  });

  it("is ok with an empty list when the installation exists but nothing is shared", async () => {
    const fetchFn = vi.fn(async (url: string | URL | Request) => (String(url).includes("access_tokens") ? json(201, { token: "tok" }) : json(200, { repositories: [] })));
    expect(await installationRepositoryList(5, cfg, fetchFn as unknown as typeof fetch)).toEqual({ status: "ok", repositories: [] });
  });
});

describe("installationForRepo with connected installations", () => {
  it("lets a connected installation read the repository it covers, with no owners list at all", async () => {
    const id = await installationForRepo({ email: "x@example.com", repo: { owner: "me", repo: "app" }, linked: [77], env: {}, cfg, fetchFn: vi.fn(async () => json(200, { id: 77 })) as unknown as typeof fetch });
    expect(id).toBe(77);
  });

  it("refuses when GitHub says another installation covers the repository", async () => {
    const id = await installationForRepo({ email: "x@example.com", repo: { owner: "them", repo: "app" }, linked: [77], env: {}, cfg, fetchFn: vi.fn(async () => json(200, { id: 88 })) as unknown as typeof fetch });
    expect(id).toBeNull();
  });
});

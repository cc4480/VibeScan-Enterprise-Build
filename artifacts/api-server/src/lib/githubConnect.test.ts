import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
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
import { startGithubStub, useRealGithub, type GithubStub } from "./githubStub.testkit";

// A throwaway key made for the test; nothing here is a GitHub credential.
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const cfg = { appId: "4242", privateKey, slug: "test-app" };

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
/** Nothing listens on port 1, so GitHub is genuinely unreachable. */
const unreachable = () => {
  process.env["GITHUB_API_URL"] = "http://127.0.0.1:1";
  process.env["GITHUB_WEB_URL"] = "http://127.0.0.1:1";
};

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
    useRealGithub();
    expect(authorizeUrl({ clientId: "Iv1.a", clientSecret: "s" }, "st ate")).toBe("https://github.com/login/oauth/authorize?client_id=Iv1.a&state=st%20ate");
  });

  it("follows GITHUB_WEB_URL, for a GitHub Enterprise Server install", () => {
    expect(authorizeUrl({ clientId: "Iv1.a", clientSecret: "s" }, "st")).toBe(`${gh.web}/login/oauth/authorize?client_id=Iv1.a&state=st`);
  });
});

describe("exchangeCode", () => {
  const client = { clientId: "id", clientSecret: "secret" };
  const TOKEN_URL = "/login/oauth/access_token";

  it("returns the user token GitHub gives for the code, and sends the client credentials", async () => {
    gh.on("POST", "web", TOKEN_URL, { json: { access_token: "tok" } });
    expect(await exchangeCode("c", client)).toBe("tok");
    expect(gh.requests).toHaveLength(1);
    expect(gh.requests[0]!.body).toContain("secret");
  });

  it("treats GitHub's 200-with-an-error answer as a rejected code", async () => {
    gh.on("POST", "web", TOKEN_URL, { json: { error: "bad_verification_code" } });
    await expect(exchangeCode("c", client)).rejects.toMatchObject({ reason: "code_rejected" });
  });

  it("calls GitHub being unreachable what it is", async () => {
    unreachable();
    await expect(exchangeCode("c", client)).rejects.toBeInstanceOf(GithubConnectError);
  });
});

describe("userInstallations", () => {
  it("keeps only this App's installations, with their account names", async () => {
    gh.on("GET", "api", "/user/installations", { json: { installations: [
      { id: 1, app_id: 4242, account: { login: "me" } },
      { id: 2, app_id: 7, account: { login: "someone-else" } },
      { id: 3, app_id: "4242", account: null },
    ] } });
    expect(await userInstallations("t", "4242")).toEqual([
      { installationId: 1, accountLogin: "me" },
      { installationId: 3, accountLogin: null },
    ]);
    expect(gh.requests[0]!.headers["authorization"]).toBe("Bearer t");
  });

  it("throws when GitHub refuses, so nothing is recorded", async () => {
    gh.on("GET", "api", "/user/installations", { status: 401, json: {} });
    await expect(userInstallations("t", "4242")).rejects.toBeInstanceOf(GithubConnectError);
  });
});

describe("installationRepositories", () => {
  it("lists what the installation can read", async () => {
    gh.on("POST", "api", "/app/installations/5/access_tokens", { status: 201, json: { token: "inst" } });
    gh.on("GET", "api", "/installation/repositories", { json: { repositories: [{ full_name: "me/app", private: true, html_url: "https://github.com/me/app" }] } });
    expect(await installationRepositories(5, cfg)).toEqual([{ fullName: "me/app", private: true, url: "https://github.com/me/app", installationId: 5 }]);
    // The repository list is read with the installation's own token, not the App's.
    expect(gh.requests.find((r) => r.path === "/installation/repositories")!.headers["authorization"]).toBe("Bearer inst");
  });

  it("is empty, not an error, when the installation is gone", async () => {
    expect(await installationRepositories(5, cfg)).toEqual([]); // the stub has no such installation: 404
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
  const pageOf = (url: string) => Number(new URL(url, "http://x").searchParams.get("page"));

  it("follows installations onto a second page", async () => {
    gh.on("GET", "api", "/user/installations", (r) => ({ json: pageOf(r.url) === 1 ? page(100, 1) : page(3, 101) }));
    const got = await userInstallations("t", "4242");
    expect(got).toHaveLength(103);
    expect(gh.requests).toHaveLength(2);
  });

  it("stops after one page when it was not full", async () => {
    gh.on("GET", "api", "/user/installations", { json: page(2, 1) });
    await userInstallations("t", "4242");
    expect(gh.requests).toHaveLength(1);
  });

  it("does not loop forever on a list that never ends", async () => {
    gh.on("GET", "api", "/user/installations", { json: page(100, 1) });
    await userInstallations("t", "4242");
    expect(gh.requests.length).toBeLessThanOrEqual(10);
  });

  it("lists more than 100 repositories", async () => {
    const repos = (n: number, start: number) => ({ repositories: Array.from({ length: n }, (_, i) => ({ full_name: `me/r${start + i}`, html_url: `https://github.com/me/r${start + i}`, private: true })) });
    gh.on("POST", "api", "/app/installations/5/access_tokens", { status: 201, json: { token: "tok" } });
    gh.on("GET", "api", "/installation/repositories", (r) => ({ json: pageOf(r.url) === 1 ? repos(100, 0) : repos(40, 100) }));
    const r = await installationRepositoryList(5, cfg);
    expect(r.status).toBe("ok");
    expect(r.repositories).toHaveLength(140);
  });
});

describe("how a connection stands", () => {
  it("is gone when GitHub says the installation no longer exists (the App was uninstalled)", async () => {
    gh.on("POST", "api", "/app/installations/5/access_tokens", { status: 404, json: {} });
    expect((await installationRepositoryList(5, cfg)).status).toBe("gone");
  });

  it("is unavailable, not gone, when GitHub cannot be asked", async () => {
    gh.on("POST", "api", "/app/installations/5/access_tokens", { status: 502, json: {} });
    expect((await installationRepositoryList(5, cfg)).status).toBe("unavailable");
    unreachable();
    expect((await installationRepositoryList(5, cfg)).status).toBe("unavailable");
    expect((await installationRepositoryList(5, null)).status).toBe("unavailable");
  });

  it("is ok with an empty list when the installation exists but nothing is shared", async () => {
    gh.on("POST", "api", "/app/installations/5/access_tokens", { status: 201, json: { token: "tok" } });
    gh.on("GET", "api", "/installation/repositories", { json: { repositories: [] } });
    expect(await installationRepositoryList(5, cfg)).toEqual({ status: "ok", repositories: [] });
  });
});

describe("installationForRepo with connected installations", () => {
  it("lets a connected installation read the repository it covers, with no owners list at all", async () => {
    gh.on("GET", "api", "/repos/me/app/installation", { json: { id: 77 } });
    expect(await installationForRepo({ email: "x@example.com", repo: { owner: "me", repo: "app" }, linked: [77], env: {}, cfg })).toBe(77);
  });

  it("refuses when GitHub says another installation covers the repository", async () => {
    gh.on("GET", "api", "/repos/them/app/installation", { json: { id: 88 } });
    expect(await installationForRepo({ email: "x@example.com", repo: { owner: "them", repo: "app" }, linked: [77], env: {}, cfg })).toBeNull();
  });
});

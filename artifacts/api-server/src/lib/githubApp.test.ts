import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { githubAppConfig, normalisePem, signAppJwt, installationToken, installUrl, GithubAppError } from "./githubApp";
import { githubInstallationSource } from "./repoSource";
import { startGithubStub, useRealGithub, type GithubStub } from "./githubStub.testkit";

let gh: GithubStub;
beforeAll(async () => { gh = await startGithubStub(); });
afterAll(async () => { await gh.stop(); useRealGithub(); });
// Each test starts from an empty stub whose endpoints are the stub's.
beforeEach(() => {
  gh.clear();
  process.env["GITHUB_API_URL"] = gh.api;
  process.env["GITHUB_WEB_URL"] = gh.web;
  process.env["GITHUB_RAW_URL"] = gh.raw;
});

// A throwaway key made for the test; nothing here is a GitHub credential.
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const cfg = { appId: "123456", privateKey, slug: "secscan-repo-reader" };

describe("githubAppConfig", () => {
  it("needs the app id and key; accepts a key with escaped newlines", () => {
    expect(githubAppConfig({})).toBeNull();
    expect(githubAppConfig({ GITHUB_APP_ID: "1" })).toBeNull();
    const escaped = githubAppConfig({ GITHUB_APP_ID: "1", GITHUB_APP_PRIVATE_KEY: privateKey.replace(/\n/g, "\\n"), GITHUB_APP_SLUG: "x" })!;
    expect(escaped.privateKey).toBe(privateKey);
    expect(() => signAppJwt(escaped)).not.toThrow();
  });
});

describe("signAppJwt", () => {
  it("is an RS256 token for the app, short-lived, that the matching public key verifies", () => {
    const now = 1_800_000_000;
    const [h, b, s] = signAppJwt(cfg, now).split(".") as [string, string, string];
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(b, "base64url").toString());
    expect(claims).toEqual({ iat: now - 60, exp: now + 540, iss: "123456" });
    expect(createVerify("RSA-SHA256").update(`${h}.${b}`).verify(publicKey, Buffer.from(s, "base64url"))).toBe(true);
  });
});

describe("installationToken, against a real server that answers like GitHub", () => {
  const TOKEN_PATH = "/app/installations/42/access_tokens";

  it("asks for one repository and read-only contents, and returns the token", async () => {
    gh.on("POST", "api", TOKEN_PATH, { status: 201, json: { token: "ghs_testtoken", expires_at: "2026-10-12T20:00:00Z" } });
    const t = await installationToken(42, "taskflow", cfg);
    expect(t).toEqual({ token: "ghs_testtoken", expiresAt: "2026-10-12T20:00:00Z" });
    expect(gh.requests).toHaveLength(1);
    const req = gh.requests[0]!;
    expect(req.method).toBe("POST");
    expect(req.path).toBe(TOKEN_PATH);
    expect(JSON.parse(req.body)).toEqual({ repositories: ["taskflow"], permissions: { contents: "read", metadata: "read" } });
    expect(String(req.headers["authorization"])).toMatch(/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
  });

  it.each([
    [404, "installation_missing"], [422, "repository_not_shared"], [500, "github_unavailable"], [401, "github_unavailable"],
  ])("HTTP %i means %s, and the message holds no credential", async (status, reason) => {
    gh.on("POST", "api", TOKEN_PATH, { status, json: { message: "x" } });
    const err = await installationToken(42, "r", cfg).catch((e) => e);
    expect(err).toBeInstanceOf(GithubAppError);
    expect(err.reason).toBe(reason);
    expect(String(err.message)).not.toMatch(/BEGIN|Bearer|ghs_/);
  });

  it("is not configured, no installation, an unreachable GitHub, and an answer with no token", async () => {
    expect((await installationToken(42, "r", null).catch((e) => e)).reason).toBe("not_configured");
    expect((await installationToken(0, "r", cfg).catch((e) => e)).reason).toBe("installation_missing");
    gh.on("POST", "api", TOKEN_PATH, { status: 201, json: {} });
    expect((await installationToken(42, "r", cfg).catch((e) => e)).reason).toBe("github_unavailable");
    // Nothing listens on port 1: the connection is genuinely refused.
    process.env["GITHUB_API_URL"] = "http://127.0.0.1:1";
    expect((await installationToken(42, "r", cfg).catch((e) => e)).reason).toBe("github_unavailable");
  });
});

describe("installUrl", () => {
  it("points at the app's install page, with a state value, or is null when there is no slug", () => {
    useRealGithub();
    expect(installUrl(cfg, "u1")).toBe("https://github.com/apps/secscan-repo-reader/installations/new?state=u1");
    expect(installUrl({ ...cfg, slug: null })).toBeNull();
    expect(installUrl(null)).toBeNull();
  });

  it("follows GITHUB_WEB_URL, for a GitHub Enterprise Server install", () => {
    expect(installUrl(cfg, "u1")).toBe(`${gh.web}/apps/secscan-repo-reader/installations/new?state=u1`);
  });
});

describe("githubInstallationSource", () => {
  const REPO = "/repos/acme/secret";

  it("sends the token to the GitHub API only, and reads a private repository", async () => {
    gh.on("GET", "api", REPO, { json: { private: true, default_branch: "main" } });
    gh.on("GET", "api", /^\/repos\/acme\/secret\/git\/trees\//, { json: { tree: [{ path: ".env", type: "blob", size: 5 }] } });
    gh.on("GET", "api", /^\/repos\/acme\/secret\/contents\/\.env$/, { text: "A=1\n" });
    const src = githubInstallationSource({ owner: "acme", repo: "secret" }, "ghs_testtoken");
    const open = await src.open();
    expect(open).toMatchObject({ ok: true, branch: "main" });
    expect(await src.read(".env", "main")).toBe("A=1\n");
    expect(gh.requests.length).toBeGreaterThan(0);
    // Every request went to the API host (never the raw-content host) and carried the credential.
    expect(gh.requests.every((r) => r.host === "api" && r.headers["authorization"] === "Bearer ghs_testtoken")).toBe(true);
  });

  it("clean twin: the public source refuses the same private repository and sends no credential", async () => {
    const { publicGithubSource } = await import("./repoSource");
    gh.on("GET", "api", REPO, { json: { private: true, default_branch: "main" } });
    expect(await publicGithubSource({ owner: "acme", repo: "secret" }).open()).toEqual({ ok: false, status: "not_public_or_missing" });
    expect(gh.requests.length).toBeGreaterThan(0);
    expect(gh.requests.every((r) => r.headers["authorization"] === undefined)).toBe(true);
  });
});

describe("normalisePem", () => {
  it("leaves a well-formed key unchanged", () => {
    expect(normalisePem(privateKey)).toBe(privateKey);
  });

  it("restores a key whose line breaks were flattened into spaces", () => {
    const flattened = privateKey.trim().replace(/\n/g, " ");
    expect(normalisePem(flattened)).toBe(privateKey);
  });

  it("restores a key with its line breaks lost altogether", () => {
    const joined = privateKey.trim().replace(/\n/g, "");
    expect(normalisePem(joined)).toBe(privateKey);
  });

  it("removes quotes that were pasted along with the value", () => {
    expect(normalisePem(`"${privateKey.trim()}"`)).toBe(privateKey);
    expect(normalisePem(`'${privateKey.trim().replace(/\n/g, "\\n")}'`)).toBe(privateKey);
  });

  it("produces a key that can sign, from each of those mangled forms", () => {
    for (const mangled of [privateKey.trim().replace(/\n/g, " "), `"${privateKey.trim()}"`]) {
      const c = githubAppConfig({ GITHUB_APP_ID: "1", GITHUB_APP_PRIVATE_KEY: mangled })!;
      expect(() => signAppJwt(c)).not.toThrow();
    }
  });

  it("returns text with no PEM markers untouched, so a wrong value still fails visibly", () => {
    expect(normalisePem("  not a key  ")).toBe("not a key");
  });
});

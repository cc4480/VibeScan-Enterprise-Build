import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { githubAppConfig, signAppJwt, installationToken, installUrl, GithubAppError } from "./githubApp";
import { githubInstallationSource } from "./repoSource";

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

describe("installationToken", () => {
  const reply = (status: number, body: unknown) => vi.fn(async () => new Response(JSON.stringify(body), { status }));

  it("asks for one repository and read-only contents, and returns the token", async () => {
    const f = reply(201, { token: "ghs_testtoken", expires_at: "2026-10-12T20:00:00Z" });
    const t = await installationToken(42, "taskflow", cfg, f as unknown as typeof fetch);
    expect(t).toEqual({ token: "ghs_testtoken", expiresAt: "2026-10-12T20:00:00Z" });
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.github.com/app/installations/42/access_tokens");
    expect(JSON.parse(init.body as string)).toEqual({ repositories: ["taskflow"], permissions: { contents: "read", metadata: "read" } });
    expect((init.headers as Record<string, string>)["Authorization"]).toMatch(/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
  });

  it.each([
    [404, "installation_missing"], [422, "repository_not_shared"], [500, "github_unavailable"], [401, "github_unavailable"],
  ])("HTTP %i means %s, and the message holds no credential", async (status, reason) => {
    const err = await installationToken(42, "r", cfg, reply(status, { message: "x" }) as unknown as typeof fetch).catch((e) => e);
    expect(err).toBeInstanceOf(GithubAppError);
    expect(err.reason).toBe(reason);
    expect(String(err.message)).not.toMatch(/BEGIN|Bearer|ghs_/);
  });

  it("is not configured, no installation, an unreachable GitHub, and an answer with no token", async () => {
    expect((await installationToken(42, "r", null).catch((e) => e)).reason).toBe("not_configured");
    expect((await installationToken(0, "r", cfg).catch((e) => e)).reason).toBe("installation_missing");
    expect((await installationToken(42, "r", cfg, vi.fn(async () => { throw new Error("ETIMEDOUT"); }) as unknown as typeof fetch).catch((e) => e)).reason).toBe("github_unavailable");
    expect((await installationToken(42, "r", cfg, reply(201, {}) as unknown as typeof fetch).catch((e) => e)).reason).toBe("github_unavailable");
  });
});

describe("installUrl", () => {
  it("points at the app's install page, with a state value, or is null when there is no slug", () => {
    expect(installUrl(cfg, "u1")).toBe("https://github.com/apps/secscan-repo-reader/installations/new?state=u1");
    expect(installUrl({ ...cfg, slug: null })).toBeNull();
    expect(installUrl(null)).toBeNull();
  });
});

describe("githubInstallationSource", () => {
  it("sends the token to api.github.com only, and reads a private repository", async () => {
    const seen: Array<{ url: string; auth: string | undefined }> = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      seen.push({ url, auth: (init?.headers as Record<string, string> | undefined)?.["Authorization"] });
      if (url.endsWith("/repos/acme/secret")) return new Response(JSON.stringify({ private: true, default_branch: "main" }), { status: 200 });
      if (url.includes("/git/trees/")) return new Response(JSON.stringify({ tree: [{ path: ".env", type: "blob", size: 5 }] }), { status: 200 });
      return new Response("A=1\n", { status: 200 });
    }));
    try {
      const src = githubInstallationSource({ owner: "acme", repo: "secret" }, "ghs_testtoken");
      const open = await src.open();
      expect(open).toMatchObject({ ok: true, branch: "main" });
      expect(await src.read(".env", "main")).toBe("A=1\n");
      expect(seen.every((s) => s.url.startsWith("https://api.github.com/") && s.auth === "Bearer ghs_testtoken")).toBe(true);
    } finally { vi.unstubAllGlobals(); }
  });

  it("clean twin: the public source refuses the same private repository and sends no credential", async () => {
    const { publicGithubSource } = await import("./repoSource");
    vi.stubGlobal("fetch", vi.fn(async (_u: string, init?: RequestInit) => {
      expect((init?.headers as Record<string, string>)["Authorization"]).toBeUndefined();
      return new Response(JSON.stringify({ private: true, default_branch: "main" }), { status: 200 });
    }));
    try { expect(await publicGithubSource({ owner: "acme", repo: "secret" }).open()).toEqual({ ok: false, status: "not_public_or_missing" }); }
    finally { vi.unstubAllGlobals(); }
  });
});

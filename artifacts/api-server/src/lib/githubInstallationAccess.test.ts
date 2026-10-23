import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { diagnoseAccess, installationForRepo, installationsOwnedBy, parseInstallationOwners } from "./githubInstallationAccess";
import { startGithubStub, useRealGithub, type GithubStub } from "./githubStub.testkit";

// A throwaway key made for the test; nothing here is a GitHub credential.
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const cfg = { appId: "123456", privateKey, slug: "test-app" };
const repo = { owner: "acme", repo: "private-app" };
const OWNERS = "1001=owner@example.com";
const LOOKUP = "/repos/acme/private-app/installation";
const TOKEN = "/app/installations/1001/access_tokens";

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

describe("parseInstallationOwners", () => {
  it("reads installation=email pairs, several emails, several installations", () => {
    const m = parseInstallationOwners("1001=A@Example.com, b@example.com ; 2002=c@example.com");
    expect([...m.get(1001)!]).toEqual(["a@example.com", "b@example.com"]);
    expect([...m.get(2002)!]).toEqual(["c@example.com"]);
  });

  it("drops malformed entries instead of guessing", () => {
    const m = parseInstallationOwners("abc=a@example.com;0=a@example.com;-5=a@example.com;1001;1001=notanemail;1001=a@example.com=b@example.com;;");
    expect(m.size).toBe(0);
  });

  it("is empty when the variable is missing", () => {
    expect(parseInstallationOwners(undefined).size).toBe(0);
    expect(parseInstallationOwners("").size).toBe(0);
  });
});

describe("installationsOwnedBy", () => {
  const owners = parseInstallationOwners("1001=owner@example.com;2002=other@example.com");
  it("matches an email case-insensitively", () => {
    expect(installationsOwnedBy("OWNER@example.com", owners)).toEqual([1001]);
  });
  it("gives nothing for an unlisted, empty or missing email", () => {
    expect(installationsOwnedBy("stranger@example.com", owners)).toEqual([]);
    expect(installationsOwnedBy("", owners)).toEqual([]);
    expect(installationsOwnedBy(null, owners)).toEqual([]);
  });
});

describe("installationForRepo", () => {
  const env = { GITHUB_INSTALLATION_OWNERS: OWNERS };

  it("returns the installation when the owner is listed and GitHub says it covers the repository", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 1001 } });
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg })).toBe(1001);
    expect(gh.requests).toHaveLength(1);
    expect(gh.requests[0]!.path).toBe(LOOKUP);
    expect(String(gh.requests[0]!.headers["authorization"])).toMatch(/^Bearer /);
  });

  it("never reaches GitHub for an account that is not listed", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 1001 } });
    expect(await installationForRepo({ email: "stranger@example.com", repo, env, cfg })).toBeNull();
    expect(gh.requests).toHaveLength(0);
  });

  it("refuses when the repository belongs to a different installation than the one the account owns", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 9999 } });
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg })).toBeNull();
  });

  it("is null when the App is not installed on the repository, or GitHub refuses", async () => {
    gh.on("GET", "api", LOOKUP, { status: 404, json: { message: "Not Found" } });
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg })).toBeNull();
    gh.on("GET", "api", LOOKUP, { status: 500, json: {} });
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg })).toBeNull();
  });

  it("fails closed when GitHub cannot be reached or answers nonsense", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: "1001" } });
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg })).toBeNull();
    // Nothing listens on port 1: the connection is genuinely refused.
    process.env["GITHUB_API_URL"] = "http://127.0.0.1:1";
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg })).toBeNull();
  });

  it("is null when the App is not configured on this server", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 1001 } });
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg: null })).toBeNull();
    expect(gh.requests).toHaveLength(0);
  });

  it("is null when no owners are configured at all", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 1001 } });
    expect(await installationForRepo({ email: "owner@example.com", repo, env: {}, cfg })).toBeNull();
  });
});

describe("diagnoseAccess", () => {
  const env = { GITHUB_INSTALLATION_OWNERS: OWNERS, GITHUB_APP_ID: "123456", GITHUB_APP_PRIVATE_KEY: privateKey };

  it("says only that the account is not listed, and never contacts GitHub, for anyone else", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 1001 } });
    const d = await diagnoseAccess({ email: "stranger@example.com", repo, env });
    expect(d).toEqual({ signedInAs: "stranger@example.com", ownersConfigured: true, listed: false });
    expect(gh.requests).toHaveLength(0);
  });

  it("reports a missing owners variable as not configured", async () => {
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env: {} });
    expect(d).toMatchObject({ ownersConfigured: false, listed: false });
  });

  it("stops at the App credentials when they are missing", async () => {
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: OWNERS } });
    expect(d).toMatchObject({ listed: true, appConfigured: false });
    expect(d.lookup).toBeUndefined();
    expect(gh.requests).toHaveLength(0);
  });

  it("stops when the private key cannot sign", async () => {
    // Assembled from pieces so no key-shaped literal sits in the source: PEM markers around text that is not a key.
    const badKey = ["-----BEGIN ", "PRIVATE KEY-----", "\nbm90IGEgcmVhbCBrZXk=\n", "-----END ", "PRIVATE KEY-----"].join("");
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env: { ...env, GITHUB_APP_PRIVATE_KEY: badKey } });
    expect(d).toMatchObject({ appConfigured: true, keySigns: false });
    expect(d.lookup).toBeUndefined();
    expect(gh.requests).toHaveLength(0);
  });

  it("walks the whole way to a minted token, without returning it", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 1001 } });
    gh.on("POST", "api", TOKEN, { status: 201, json: { token: "TOKEN-VALUE-MUST-NOT-APPEAR", expires_at: "2030-01-01T00:00:00Z" } });
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env });
    expect(d).toMatchObject({ listed: true, appConfigured: true, keySigns: true, lookup: { status: 200, installationId: 1001, coveredByOwnedInstallation: true }, token: "minted" });
    expect(JSON.stringify(d)).not.toContain("TOKEN-VALUE-MUST-NOT-APPEAR");
    expect(JSON.stringify(d)).not.toContain("BEGIN");
  });

  it("shows when the App is not installed on the repository", async () => {
    gh.on("GET", "api", LOOKUP, { status: 404, json: {} });
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env });
    expect(d).toMatchObject({ lookup: { status: 404, installationId: null, coveredByOwnedInstallation: false }, token: "skipped" });
  });

  it("shows when GitHub names an installation the account does not own", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 9999 } });
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env });
    expect(d).toMatchObject({ lookup: { installationId: 9999, coveredByOwnedInstallation: false }, token: "skipped" });
  });

  it("gives the reason when a token cannot be minted", async () => {
    gh.on("GET", "api", LOOKUP, { json: { id: 1001 } });
    gh.on("POST", "api", TOKEN, { status: 422, json: {} });
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env });
    expect(d.token).toBe("repository_not_shared");
  });
});

describe("owners variable handling", () => {
  it("accepts a value that still carries the quotes it was pasted with", () => {
    expect([...parseInstallationOwners('"1001=owner@example.com"').keys()]).toEqual([1001]);
    expect([...parseInstallationOwners("'1001=owner@example.com'").keys()]).toEqual([1001]);
  });

  it("does not strip quotes that are not a matching pair around the whole value", () => {
    expect(parseInstallationOwners('"1001=owner@example.com').size).toBe(0);
  });

  it("tells a missing variable from one that is present but unreadable", async () => {
    const missing = await diagnoseAccess({ email: "owner@example.com", repo, env: {} });
    expect(missing).toMatchObject({ ownersConfigured: false, ownersVariable: "missing" });
    for (const bad of ["170782825", "owner@example.com", "170782825:owner@example.com", "abc=owner@example.com"]) {
      const d = await diagnoseAccess({ email: "owner@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: bad } });
      expect(d).toMatchObject({ ownersConfigured: false, ownersVariable: "unreadable" });
    }
  });

  it("leaves the field out when the variable reads fine", async () => {
    const d = await diagnoseAccess({ email: "stranger@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: OWNERS } });
    expect(d.ownersVariable).toBeUndefined();
  });
});

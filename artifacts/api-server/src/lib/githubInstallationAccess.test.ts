import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { diagnoseAccess, installationForRepo, installationsOwnedBy, parseInstallationOwners } from "./githubInstallationAccess";

// A throwaway key made for the test; nothing here is a GitHub credential.
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const cfg = { appId: "123456", privateKey, slug: "test-app" };
const repo = { owner: "acme", repo: "private-app" };
const OWNERS = "1001=owner@example.com";

const answer = (status: number, body: unknown) => vi.fn(async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;

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
  it("returns the installation when the owner is listed and GitHub says it covers the repository", async () => {
    const fetchFn = answer(200, { id: 1001 });
    const id = await installationForRepo({ email: "owner@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: OWNERS }, cfg, fetchFn });
    expect(id).toBe(1001);
    const url = (fetchFn as unknown as { mock: { calls: [string][] } }).mock.calls[0]![0];
    expect(url).toBe("https://api.github.com/repos/acme/private-app/installation");
  });

  it("never reaches GitHub for an account that is not listed", async () => {
    const fetchFn = answer(200, { id: 1001 });
    const id = await installationForRepo({ email: "stranger@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: OWNERS }, cfg, fetchFn });
    expect(id).toBeNull();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("refuses when the repository belongs to a different installation than the one the account owns", async () => {
    const id = await installationForRepo({ email: "owner@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: OWNERS }, cfg, fetchFn: answer(200, { id: 9999 }) });
    expect(id).toBeNull();
  });

  it("is null when the App is not installed on the repository, or GitHub refuses", async () => {
    const env = { GITHUB_INSTALLATION_OWNERS: OWNERS };
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg, fetchFn: answer(404, { message: "Not Found" }) })).toBeNull();
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg, fetchFn: answer(500, {}) })).toBeNull();
  });

  it("fails closed when GitHub cannot be reached or answers nonsense", async () => {
    const env = { GITHUB_INSTALLATION_OWNERS: OWNERS };
    const down = vi.fn(async () => { throw new Error("network"); }) as unknown as typeof fetch;
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg, fetchFn: down })).toBeNull();
    expect(await installationForRepo({ email: "owner@example.com", repo, env, cfg, fetchFn: answer(200, { id: "1001" }) })).toBeNull();
  });

  it("is null when the App is not configured on this server", async () => {
    const fetchFn = answer(200, { id: 1001 });
    expect(await installationForRepo({ email: "owner@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: OWNERS }, cfg: null, fetchFn })).toBeNull();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("is null when no owners are configured at all", async () => {
    expect(await installationForRepo({ email: "owner@example.com", repo, env: {}, cfg, fetchFn: answer(200, { id: 1001 }) })).toBeNull();
  });
});

describe("diagnoseAccess", () => {
  const env = { GITHUB_INSTALLATION_OWNERS: OWNERS, GITHUB_APP_ID: "123456", GITHUB_APP_PRIVATE_KEY: privateKey };
  const routes = (lookup: Response, tokenRes: Response) =>
    vi.fn(async (url: string | URL | Request) => (String(url).endsWith("/installation") ? lookup : tokenRes)) as unknown as typeof fetch;
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

  it("says only that the account is not listed, and never contacts GitHub, for anyone else", async () => {
    const fetchFn = answer(200, { id: 1001 });
    const d = await diagnoseAccess({ email: "stranger@example.com", repo, env, fetchFn });
    expect(d).toEqual({ signedInAs: "stranger@example.com", ownersConfigured: true, listed: false });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("reports a missing owners variable as not configured", async () => {
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env: {}, fetchFn: answer(200, {}) });
    expect(d).toMatchObject({ ownersConfigured: false, listed: false });
  });

  it("stops at the App credentials when they are missing", async () => {
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: OWNERS }, fetchFn: answer(200, {}) });
    expect(d).toMatchObject({ listed: true, appConfigured: false });
    expect(d.lookup).toBeUndefined();
  });

  it("stops when the private key cannot sign", async () => {
    // Assembled from pieces so no key-shaped literal sits in the source: PEM markers around text that is not a key.
    const badKey = ["-----BEGIN ", "PRIVATE KEY-----", "\nbm90IGEgcmVhbCBrZXk=\n", "-----END ", "PRIVATE KEY-----"].join("");
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env: { ...env, GITHUB_APP_PRIVATE_KEY: badKey }, fetchFn: answer(200, {}) });
    expect(d).toMatchObject({ appConfigured: true, keySigns: false });
    expect(d.lookup).toBeUndefined();
  });

  it("walks the whole way to a minted token, without returning it", async () => {
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env, fetchFn: routes(json(200, { id: 1001 }), json(201, { token: "TOKEN-VALUE-MUST-NOT-APPEAR", expires_at: "2030-01-01T00:00:00Z" })) });
    expect(d).toMatchObject({ listed: true, appConfigured: true, keySigns: true, lookup: { status: 200, installationId: 1001, coveredByOwnedInstallation: true }, token: "minted" });
    expect(JSON.stringify(d)).not.toContain("TOKEN-VALUE-MUST-NOT-APPEAR");
    expect(JSON.stringify(d)).not.toContain("BEGIN");
  });

  it("shows when the App is not installed on the repository", async () => {
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env, fetchFn: routes(json(404, {}), json(201, {})) });
    expect(d).toMatchObject({ lookup: { status: 404, installationId: null, coveredByOwnedInstallation: false }, token: "skipped" });
  });

  it("shows when GitHub names an installation the account does not own", async () => {
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env, fetchFn: routes(json(200, { id: 9999 }), json(201, {})) });
    expect(d).toMatchObject({ lookup: { installationId: 9999, coveredByOwnedInstallation: false }, token: "skipped" });
  });

  it("gives the reason when a token cannot be minted", async () => {
    const d = await diagnoseAccess({ email: "owner@example.com", repo, env, fetchFn: routes(json(200, { id: 1001 }), json(422, {})) });
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
    const missing = await diagnoseAccess({ email: "owner@example.com", repo, env: {}, fetchFn: answer(200, {}) });
    expect(missing).toMatchObject({ ownersConfigured: false, ownersVariable: "missing" });
    for (const bad of ["170782825", "owner@example.com", "170782825:owner@example.com", "abc=owner@example.com"]) {
      const d = await diagnoseAccess({ email: "owner@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: bad }, fetchFn: answer(200, {}) });
      expect(d).toMatchObject({ ownersConfigured: false, ownersVariable: "unreadable" });
    }
  });

  it("leaves the field out when the variable reads fine", async () => {
    const d = await diagnoseAccess({ email: "stranger@example.com", repo, env: { GITHUB_INSTALLATION_OWNERS: OWNERS }, fetchFn: answer(200, {}) });
    expect(d.ownersVariable).toBeUndefined();
  });
});

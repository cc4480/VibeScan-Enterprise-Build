import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { installationForRepo, installationsOwnedBy, parseInstallationOwners } from "./githubInstallationAccess";

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

import { describe, it, expect, vi, beforeEach } from "vitest";
import { randomBytes } from "node:crypto";

let account: { passwordHash: string | null; emailVerifiedAt: Date | null } | undefined;

vi.mock("@workspace/db", () => {
  const chain: Record<string, unknown> = {};
  Object.assign(chain, {
    select: () => chain,
    from: () => chain,
    where: () => chain,
    limit: () => Promise.resolve(account ? [account] : []),
  });
  return { db: chain, usersTable: { id: "id", passwordHash: "password_hash", emailVerifiedAt: "email_verified_at" } };
});
vi.mock("drizzle-orm", () => ({ eq: () => ({}) }));

import { prepareScanCredentials } from "./scansCredentials";
import { decryptCredentials } from "../lib/scanCredentials";

const session = (cookie: string) => ({ mode: "session" as const, authorized: true, cookie });
const log = { info: vi.fn() } as never;
const verified = () => ({ passwordHash: "x", emailVerifiedAt: new Date() });

beforeEach(() => {
  process.env["ENCRYPTION_KEY"] = randomBytes(32).toString("base64");
  account = verified();
  vi.clearAllMocks();
});

describe("prepareScanCredentials", () => {
  it("passes a scan with no logins straight through", async () => {
    const r = await prepareScanCredentials("u", undefined, undefined, log);
    expect(r).toEqual({ ok: true, credentialsEncrypted: null, secondaryCredentialsEncrypted: null, credentialsAuthorizedAt: null });
  });

  it("refuses logins from an anonymous account (403)", async () => {
    account = { passwordHash: null, emailVerifiedAt: null };
    const r = await prepareScanCredentials("u", session("a=1"), undefined, log);
    expect(r).toMatchObject({ ok: false, status: 403 });
    expect((r as { error: string }).error).toMatch(/needs a registered account/);
  });

  it("refuses logins from an unverified email (403)", async () => {
    account = { passwordHash: "x", emailVerifiedAt: null };
    const r = await prepareScanCredentials("u", session("a=1"), undefined, log);
    expect(r).toEqual({ ok: false, status: 403, error: "Verify your email address before storing login details for a scan." });
  });

  it("refuses logins the scanner could not use (400)", async () => {
    const r = await prepareScanCredentials("u", { mode: "session", authorized: false, cookie: "a=1" }, undefined, log);
    expect(r).toMatchObject({ ok: false, status: 400 });
    expect((r as { error: string }).error).toMatch(/authorised/);
  });

  it("encrypts the login, stamps when it was authorised, and logs the mode and not the secret", async () => {
    const r = await prepareScanCredentials("u", session("sid=secret"), undefined, log);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.credentialsEncrypted).not.toContain("secret");
    expect(decryptCredentials(r.credentialsEncrypted!)).toMatchObject({ cookie: "sid=secret" });
    expect(r.credentialsAuthorizedAt).toBeInstanceOf(Date);
    expect(r.secondaryCredentialsEncrypted).toBeNull();
    expect(JSON.stringify((log as { info: { mock: { calls: unknown[] } } }).info.mock.calls)).not.toContain("secret");
  });

  it("encrypts a second, different account", async () => {
    const r = await prepareScanCredentials("u", session("a=1"), session("b=2"), log);
    expect(r).toMatchObject({ ok: true });
    expect((r as { secondaryCredentialsEncrypted: string }).secondaryCredentialsEncrypted).toBeTruthy();
  });

  it("refuses the same account twice (400)", async () => {
    const r = await prepareScanCredentials("u", session("a=1"), session("a=1"), log);
    expect(r).toMatchObject({ ok: false, status: 400 });
    expect((r as { error: string }).error).toMatch(/^Second account: this is the same account/);
  });

  it("refuses an unusable second account with the 'Second account' prefix (400)", async () => {
    const r = await prepareScanCredentials("u", session("a=1"), { mode: "session", authorized: true, cookie: " " }, log);
    expect(r).toMatchObject({ ok: false, status: 400 });
    expect((r as { error: string }).error).toMatch(/^Second account: /);
  });

  it("refuses a second account without a first (400)", async () => {
    const r = await prepareScanCredentials("u", undefined, session("b=2"), log);
    expect(r).toEqual({ ok: false, status: 400, error: "A second account only works alongside a first one. Add primary credentials too." });
  });
});

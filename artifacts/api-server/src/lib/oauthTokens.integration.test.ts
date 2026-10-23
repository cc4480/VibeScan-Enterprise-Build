/**
 * The OAuth token lifecycle against a REAL Postgres: every rule here is an atomic
 * statement or a revocation predicate that a mock would pass regardless. Skips unless
 * a throwaway database is supplied (see billing.integration.test.ts).
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { challengeFor } from "./oauthPkce";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = challengeFor(VERIFIER);
const REDIRECT = "http://127.0.0.1:5000/cb";

suite("OAuth tokens (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let oauth: typeof import("./oauthTokens");
  let clients: typeof import("./oauthClients");
  let tokens: typeof import("./apiTokens");
  let sql: typeof import("drizzle-orm").sql;
  let userId = "";
  let clientId = "";

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    oauth = await import("./oauthTokens");
    clients = await import("./oauthClients");
    tokens = await import("./apiTokens");
    sql = (await import("drizzle-orm")).sql;
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });

  beforeEach(async () => {
    const { db, usersTable } = dbMod;
    await db.execute(sql`TRUNCATE oauth_codes, oauth_refresh_tokens, oauth_clients, api_tokens CASCADE`);
    const [u] = await db.insert(usersTable).values({ email: `oauth-${Date.now()}-${Math.random()}@example.com` }).returning({ id: usersTable.id });
    userId = u!.id;
    clientId = (await clients.registerClient("Test Editor", [REDIRECT])).clientId;
  });

  const authorize = () => oauth.issueAuthorizationCode({ userId, clientId, redirectUri: REDIRECT, codeChallenge: CHALLENGE });
  const exchange = (code: string, over: Record<string, unknown> = {}) =>
    oauth.exchangeCode({ code, clientId, redirectUri: REDIRECT, codeVerifier: VERIFIER, ...over });
  async function mint() {
    const r = await exchange(await authorize());
    if (!r.ok) throw new Error("exchange failed: " + r.description);
    return r.tokens;
  }
  const mcp = (access: string) => tokens.authenticateApiToken(`Bearer ${access}`, "mcp");

  describe("authorization code", () => {
    it("trades for tokens that authenticate on the MCP endpoint, as the person who approved", async () => {
      const t = await mint();
      expect(t).toMatchObject({ token_type: "Bearer", expires_in: 3600, scope: "mcp" });
      expect((await mcp(t.access_token))?.id).toBe(userId);
    });

    it("gives a token that reaches MCP only, never the REST API", async () => {
      const t = await mint();
      expect(await tokens.authenticateApiToken(`Bearer ${t.access_token}`, "api")).toBeNull();
    });

    it("works once: replaying the code is refused AND revokes what it produced", async () => {
      const code = await authorize();
      const first = await exchange(code);
      expect(first.ok).toBe(true);
      const access = (first as { ok: true; tokens: { access_token: string; refresh_token: string } }).tokens;
      expect((await mcp(access.access_token))?.id).toBe(userId);

      expect((await exchange(code)).ok).toBe(false);
      // The stolen-code alarm: the legitimate tokens are gone too.
      expect(await mcp(access.access_token)).toBeNull();
      expect((await oauth.refreshTokens({ refreshToken: access.refresh_token, clientId })).ok).toBe(false);
    });

    it("lets exactly one of two simultaneous exchanges win", async () => {
      const code = await authorize();
      const results = await Promise.all([exchange(code), exchange(code), exchange(code)]);
      expect(results.filter((r) => r.ok)).toHaveLength(1);
    });

    it("refuses the wrong PKCE verifier, and the code is spent even so", async () => {
      const code = await authorize();
      expect((await exchange(code, { codeVerifier: "x".repeat(43) })).ok).toBe(false);
      expect((await exchange(code)).ok).toBe(false);
    });

    it("refuses another app's client_id and a different redirect_uri", async () => {
      const other = (await clients.registerClient("Other", ["http://127.0.0.1:6000/cb"])).clientId;
      expect((await exchange(await authorize(), { clientId: other })).ok).toBe(false);
      expect((await exchange(await authorize(), { redirectUri: "http://127.0.0.1:5000/other" })).ok).toBe(false);
    });

    it("refuses an expired code", async () => {
      const code = await authorize();
      await dbMod.db.execute(sql`UPDATE oauth_codes SET expires_at = now() - interval '1 minute'`);
      expect((await exchange(code)).ok).toBe(false);
    });

    it("refuses nonsense without touching the database", async () => {
      for (const bad of [undefined, null, 5, "", "short", "x".repeat(300)]) expect((await exchange(bad as string)).ok).toBe(false);
    });
  });

  describe("access tokens", () => {
    it("stop working after their hour", async () => {
      const t = await mint();
      await dbMod.db.execute(sql`UPDATE api_tokens SET expires_at = now() - interval '1 minute'`);
      expect(await mcp(t.access_token)).toBeNull();
    });

    it("do not count against, or appear in, the pasted-token list", async () => {
      await mint();
      expect(await tokens.liveTokenCount(userId)).toBe(0);
    });
  });

  describe("refresh tokens", () => {
    it("rotate: a new pair works and the old access token stops", async () => {
      const t = await mint();
      const r = await oauth.refreshTokens({ refreshToken: t.refresh_token, clientId });
      expect(r.ok).toBe(true);
      const next = (r as { ok: true; tokens: { access_token: string; refresh_token: string } }).tokens;
      expect(next.refresh_token).not.toBe(t.refresh_token);
      expect((await mcp(next.access_token))?.id).toBe(userId);
      expect(await mcp(t.access_token)).toBeNull();
    });

    it("presenting a used refresh token revokes the whole family, including the newest tokens", async () => {
      const t = await mint();
      const next = (await oauth.refreshTokens({ refreshToken: t.refresh_token, clientId })) as { ok: true; tokens: { access_token: string; refresh_token: string } };
      // The old refresh token again: someone kept a copy.
      expect((await oauth.refreshTokens({ refreshToken: t.refresh_token, clientId })).ok).toBe(false);
      expect(await mcp(next.tokens.access_token)).toBeNull();
      expect((await oauth.refreshTokens({ refreshToken: next.tokens.refresh_token, clientId })).ok).toBe(false);
    });

    it("lets exactly one of simultaneous refreshes win", async () => {
      const t = await mint();
      const results = await Promise.all([1, 2, 3].map(() => oauth.refreshTokens({ refreshToken: t.refresh_token, clientId })));
      expect(results.filter((r) => r.ok)).toHaveLength(1);
    });

    it("burns the family when another app presents the token", async () => {
      const t = await mint();
      const other = (await clients.registerClient("Thief", ["http://127.0.0.1:7000/cb"])).clientId;
      expect((await oauth.refreshTokens({ refreshToken: t.refresh_token, clientId: other })).ok).toBe(false);
      expect(await mcp(t.access_token)).toBeNull();
    });

    it("refuses an expired refresh token", async () => {
      const t = await mint();
      await dbMod.db.execute(sql`UPDATE oauth_refresh_tokens SET expires_at = now() - interval '1 minute'`);
      expect((await oauth.refreshTokens({ refreshToken: t.refresh_token, clientId })).ok).toBe(false);
    });
  });

  describe("revoking and connected apps", () => {
    it("lists a connected app and forgets it once disconnected", async () => {
      await mint();
      const list = await oauth.listConnections(userId);
      expect(list).toHaveLength(1);
      expect(list[0]).toMatchObject({ clientId, name: "Test Editor" });

      await oauth.disconnectApp(userId, clientId);
      expect(await oauth.listConnections(userId)).toHaveLength(0);
    });

    it("disconnecting kills the access token and the refresh token", async () => {
      const t = await mint();
      await oauth.disconnectApp(userId, clientId);
      expect(await mcp(t.access_token)).toBeNull();
      expect((await oauth.refreshTokens({ refreshToken: t.refresh_token, clientId })).ok).toBe(false);
    });

    it("cannot disconnect someone else's connection", async () => {
      const t = await mint();
      expect(await oauth.disconnectApp("someone-else", clientId)).toBe(0);
      expect((await mcp(t.access_token))?.id).toBe(userId);
    });

    it("revokes by token (RFC 7009) for either kind, and says nothing about unknown ones", async () => {
      const a = await mint();
      await oauth.revokeByToken(a.refresh_token);
      expect(await mcp(a.access_token)).toBeNull();

      const b = await mint();
      await oauth.revokeByToken(b.access_token);
      expect(await mcp(b.access_token)).toBeNull();
      await expect(oauth.revokeByToken("not-a-token-that-exists-at-all-0000")).resolves.toBeUndefined();
    });

    it("revokeAllAccess (password reset) kills connected apps, refresh tokens and pasted API tokens", async () => {
      const t = await mint();
      const { db, apiTokensTable } = dbMod;
      const { token, hash, prefix } = tokens.generateToken();
      await db.insert(apiTokensTable).values({ userId, name: "ci", tokenHash: hash, prefix, scope: "mcp" });
      expect((await mcp(token))?.id).toBe(userId);

      await oauth.revokeAllAccess(userId);

      expect(await mcp(token)).toBeNull();
      expect(await mcp(t.access_token)).toBeNull();
      const again = await oauth.refreshTokens({ refreshToken: t.refresh_token, clientId });
      expect(again.ok).toBe(false);
    });
  });
});

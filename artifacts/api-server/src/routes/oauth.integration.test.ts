/**
 * The whole OAuth flow over HTTP against a REAL Postgres: register, sign the person
 * in and ask, approve, trade the code, use the token on MCP, refresh, disconnect.
 * Skips unless a throwaway database is supplied (see billing.integration.test.ts).
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import { challengeFor } from "../lib/oauthPkce";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = challengeFor(VERIFIER);
const REDIRECT = "http://127.0.0.1:5000/callback";

type Res = Omit<Response, "json"> & { json(): Promise<any> };

suite("OAuth over HTTP (real Postgres)", () => {
  let base = "";
  let server: ReturnType<ReturnType<typeof express>["listen"]>;
  let dbMod: typeof import("@workspace/db");
  let tokens: typeof import("../lib/apiTokens");
  let sql: typeof import("drizzle-orm").sql;
  let alice = "";
  let bob = "";

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    tokens = await import("../lib/apiTokens");
    sql = (await import("drizzle-orm")).sql;
    const { default: metadata } = await import("./oauthMetadata");
    const { default: pub } = await import("./oauthPublic");
    const { default: consent } = await import("./oauthConsent");

    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(metadata);
    // Stand-in for the session middleware: "x-user" is who is signed in.
    app.use((req, _res, next) => {
      const id = req.headers["x-user"];
      Object.assign(req, {
        log: { info() {}, warn() {}, error() {} },
        isAuthenticated: () => typeof id === "string",
        user: typeof id === "string" ? { id, email: `${id}@example.com` } : undefined,
      });
      next();
    });
    app.use("/api", pub);
    app.use("/api", consent);
    await new Promise<void>((r) => { server = app.listen(0, "127.0.0.1", () => r()); });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 60_000);
  afterAll(async () => { server?.close(); await dbMod?.pool?.end?.(); });

  beforeEach(async () => {
    await dbMod.db.execute(sql`TRUNCATE oauth_codes, oauth_refresh_tokens, oauth_clients, api_tokens CASCADE`);
    const { db, usersTable } = dbMod;
    const make = async (label: string) => (await db.insert(usersTable).values({ email: `${label}-${Date.now()}-${Math.random()}@example.com` }).returning({ id: usersTable.id }))[0]!.id;
    alice = await make("alice");
    bob = await make("bob");
  });

  const call = (path: string, init: { method?: string; user?: string; json?: unknown; form?: Record<string, string> } = {}) =>
    fetch(base + path, {
      method: init.method ?? (init.json || init.form ? "POST" : "GET"),
      headers: {
        ...(init.user ? { "x-user": init.user } : {}),
        ...(init.json ? { "content-type": "application/json" } : {}),
        ...(init.form ? { "content-type": "application/x-www-form-urlencoded" } : {}),
      },
      ...(init.json ? { body: JSON.stringify(init.json) } : {}),
      ...(init.form ? { body: new URLSearchParams(init.form).toString() } : {}),
      redirect: "manual",
    }) as Promise<Res>;

  const register = async (uris = [REDIRECT]) => (await (await call("/api/oauth/register", { json: { client_name: "Test Editor", redirect_uris: uris, token_endpoint_auth_method: "none" } })).json()).client_id as string;
  const authorizeQuery = (clientId: string, over: Record<string, string> = {}) =>
    "?" + new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: CHALLENGE, code_challenge_method: "S256", state: "xyz", ...over });

  async function approve(clientId: string, user = alice) {
    const preview = await (await call("/api/oauth/authorize/preview" + authorizeQuery(clientId), { user })).json();
    const decision = await (await call("/api/oauth/authorize/decision", { user, json: { consent: preview.consent, approve: true } })).json();
    return new URL(decision.redirectUrl);
  }
  const tokenRequest = (form: Record<string, string>) => call("/api/oauth/token", { form });

  it("serves discovery documents that point at working endpoints", async () => {
    const as = await (await call("/.well-known/oauth-authorization-server")).json();
    expect(as.code_challenge_methods_supported).toEqual(["S256"]);
    expect(as.token_endpoint_auth_methods_supported).toEqual(["none"]);
    expect(as.registration_endpoint).toContain("/api/oauth/register");
    const rs = await (await call("/.well-known/oauth-protected-resource/api/mcp")).json();
    expect(rs.resource).toMatch(/\/api\/mcp$/);
    expect(rs.authorization_servers).toEqual([as.issuer]);
  });

  it("runs the whole flow: register, approve, exchange, use on MCP, refresh, disconnect", async () => {
    const clientId = await register();
    const back = await approve(clientId);
    expect(back.origin + back.pathname).toBe(REDIRECT);
    expect(back.searchParams.get("state")).toBe("xyz");
    expect(back.searchParams.get("iss")).toBeTruthy();
    const code = back.searchParams.get("code")!;

    const res = await tokenRequest({ grant_type: "authorization_code", client_id: clientId, code, redirect_uri: REDIRECT, code_verifier: VERIFIER });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const t = await res.json();
    expect(t.token_type).toBe("Bearer");
    expect((await tokens.authenticateApiToken(`Bearer ${t.access_token}`, "mcp"))?.id).toBe(alice);

    const next = await (await tokenRequest({ grant_type: "refresh_token", client_id: clientId, refresh_token: t.refresh_token })).json();
    expect(next.access_token).toBeTruthy();
    expect(await tokens.authenticateApiToken(`Bearer ${t.access_token}`, "mcp")).toBeNull();

    const list = await (await call("/api/account/connections", { user: alice })).json();
    expect(list.connections).toHaveLength(1);
    expect(list.connections[0].name).toBe("Test Editor");
    expect((await call(`/api/account/connections/${clientId}`, { method: "DELETE", user: alice })).status).toBe(204);
    expect(await tokens.authenticateApiToken(`Bearer ${next.access_token}`, "mcp")).toBeNull();
  });

  describe("registration", () => {
    it.each([
      [["javascript:alert(1)"], "invalid_redirect_uri"],
      [["http://evil.example/cb"], "invalid_redirect_uri"],
      [[], "invalid_redirect_uri"],
    ])("refuses redirect_uris %j", async (uris, error) => {
      const res = await call("/api/oauth/register", { json: { redirect_uris: uris } });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe(error);
    });

    it("refuses a client that asks for a secret", async () => {
      const res = await call("/api/oauth/register", { json: { redirect_uris: [REDIRECT], token_endpoint_auth_method: "client_secret_post" } });
      expect(res.status).toBe(400);
    });
  });

  describe("the authorization request", () => {
    it("needs a signed-in account", async () => {
      const clientId = await register();
      expect((await call("/api/oauth/authorize/preview" + authorizeQuery(clientId))).status).toBe(401);
    });

    it("does NOT redirect for an unknown app or an unregistered redirect address, it tells the person", async () => {
      const clientId = await register();
      const unknown = await call("/api/oauth/authorize/preview" + authorizeQuery("mcp_doesnotexistdoesnotexist"), { user: alice });
      expect(unknown.status).toBe(400);
      expect((await unknown.json()).redirectUrl).toBeUndefined();
      for (const uri of ["http://127.0.0.1:5000/other", "http://127.0.0.1:5000/callback/", "https://evil.example/callback"]) {
        const res = await call("/api/oauth/authorize/preview" + authorizeQuery(clientId, { redirect_uri: uri }), { user: alice });
        expect(res.status, uri).toBe(400);
        expect((await res.json()).redirectUrl).toBeUndefined();
      }
    });

    it.each([
      [{ code_challenge_method: "plain" }, "invalid_request"],
      [{ code_challenge: "tooshort" }, "invalid_request"],
      [{ response_type: "token" }, "unsupported_response_type"],
      [{ scope: "mcp admin" }, "invalid_scope"],
      [{ resource: "https://elsewhere.example/api" }, "invalid_target"],
    ])("sends %j back to the app as %s", async (over, error) => {
      const clientId = await register();
      const body = await (await call("/api/oauth/authorize/preview" + authorizeQuery(clientId, over), { user: alice })).json();
      const back = new URL(body.redirectUrl);
      expect(back.searchParams.get("error")).toBe(error);
      expect(back.searchParams.get("state")).toBe("xyz");
      expect(back.searchParams.get("code")).toBeNull();
    });

    it("tells the person who is asking, where they go back to, and what it can do", async () => {
      const clientId = await register();
      const body = await (await call("/api/oauth/authorize/preview" + authorizeQuery(clientId), { user: alice })).json();
      expect(body.client.name).toBe("Test Editor");
      expect(body.redirect).toEqual({ host: "127.0.0.1:5000", kind: "local" });
      expect(body.access.length).toBeGreaterThan(0);
    });
  });

  describe("the decision", () => {
    it("declining sends access_denied and never issues a code", async () => {
      const clientId = await register();
      const preview = await (await call("/api/oauth/authorize/preview" + authorizeQuery(clientId), { user: alice })).json();
      const out = await (await call("/api/oauth/authorize/decision", { user: alice, json: { consent: preview.consent, approve: false } })).json();
      const back = new URL(out.redirectUrl);
      expect(back.searchParams.get("error")).toBe("access_denied");
      expect(back.searchParams.get("code")).toBeNull();
    });

    it("refuses a consent token made for someone else, a missing one, and a forged one", async () => {
      const clientId = await register();
      const preview = await (await call("/api/oauth/authorize/preview" + authorizeQuery(clientId), { user: alice })).json();
      expect((await call("/api/oauth/authorize/decision", { user: bob, json: { consent: preview.consent, approve: true } })).status).toBe(400);
      expect((await call("/api/oauth/authorize/decision", { user: alice, json: { approve: true } })).status).toBe(400);
      expect((await call("/api/oauth/authorize/decision", { user: alice, json: { consent: preview.consent + "x", approve: true } })).status).toBe(400);
      expect((await call("/api/oauth/authorize/decision", { json: { consent: preview.consent, approve: true } })).status).toBe(401);
    });

    it("only an explicit approve=true approves", async () => {
      const clientId = await register();
      const preview = await (await call("/api/oauth/authorize/preview" + authorizeQuery(clientId), { user: alice })).json();
      for (const approve of ["true", 1, undefined, null]) {
        const out = await (await call("/api/oauth/authorize/decision", { user: alice, json: { consent: preview.consent, approve } })).json();
        expect(new URL(out.redirectUrl).searchParams.get("code")).toBeNull();
      }
    });
  });

  describe("the token endpoint", () => {
    it("refuses an unknown client, an unknown grant, and a code with the wrong verifier", async () => {
      const clientId = await register();
      expect((await tokenRequest({ grant_type: "authorization_code", client_id: "mcp_doesnotexistdoesnotexist", code: "x" })).status).toBe(401);
      const unsupported = await tokenRequest({ grant_type: "password", client_id: clientId });
      expect(unsupported.status).toBe(400);
      expect((await unsupported.json()).error).toBe("unsupported_grant_type");

      const code = (await approve(clientId)).searchParams.get("code")!;
      const bad = await tokenRequest({ grant_type: "authorization_code", client_id: clientId, code, redirect_uri: REDIRECT, code_verifier: "y".repeat(43) });
      expect(bad.status).toBe(400);
      expect((await bad.json()).error).toBe("invalid_grant");
    });

    it("accepts JSON as well as form bodies", async () => {
      const clientId = await register();
      const code = (await approve(clientId)).searchParams.get("code")!;
      const res = await call("/api/oauth/token", { json: { grant_type: "authorization_code", client_id: clientId, code, redirect_uri: REDIRECT, code_verifier: VERIFIER } });
      expect(res.status).toBe(200);
    });

    it("revoke always answers 200, and really revokes", async () => {
      const clientId = await register();
      const code = (await approve(clientId)).searchParams.get("code")!;
      const t = await (await tokenRequest({ grant_type: "authorization_code", client_id: clientId, code, redirect_uri: REDIRECT, code_verifier: VERIFIER })).json();
      expect((await call("/api/oauth/revoke", { form: { token: t.refresh_token } })).status).toBe(200);
      expect((await call("/api/oauth/revoke", { form: { token: "never-issued-never-issued-0000" } })).status).toBe(200);
      expect(await tokens.authenticateApiToken(`Bearer ${t.access_token}`, "mcp")).toBeNull();
    });
  });

  it("does not let one person disconnect another's app", async () => {
    const clientId = await register();
    await tokenRequest({ grant_type: "authorization_code", client_id: clientId, code: (await approve(clientId)).searchParams.get("code")!, redirect_uri: REDIRECT, code_verifier: VERIFIER });
    expect((await call(`/api/account/connections/${clientId}`, { method: "DELETE", user: bob })).status).toBe(404);
    expect((await (await call("/api/account/connections", { user: alice })).json()).connections).toHaveLength(1);
  });
});

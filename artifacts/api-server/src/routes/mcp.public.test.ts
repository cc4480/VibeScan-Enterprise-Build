import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { useRealDb, TEST_DATABASE_URL, openDb, uniqueEmail } from "../lib/realDb.testkit";

useRealDb();

/**
 * Without a token, directories may connect and list the tools (so their health checks pass) and nothing else. Every tool
 * call still needs a token. The token checks run against real tokens in a REAL Postgres (BILLING_TEST_DATABASE_URL).
 */

// Imported only now: the db module this pulls in must be built against the real database URL set above.
const { default: mcpRouter, isPublicMcpRequest } = await import("./mcp");

const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  (req as any).log = { info() {}, warn() {}, error() {} };
  next();
});
app.use(mcpRouter);

const HEADERS = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
const rpc = (method: string, params: Record<string, unknown> = {}, id: number | undefined = 1) =>
  id === undefined ? { jsonrpc: "2.0", method, params } : { jsonrpc: "2.0", id, method, params };
const INIT = rpc("initialize", {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "health-check", version: "1" },
});

/** Streamable HTTP may answer as JSON or as one SSE event; read either. */
function payload(res: request.Response): any {
  const text = res.text ?? "";
  const data = text.split("\n").find((l) => l.startsWith("data: "));
  return data ? JSON.parse(data.slice(6)) : JSON.parse(text);
}

describe("isPublicMcpRequest", () => {
  it("allows the handshake and the tool list", () => {
    for (const m of ["initialize", "notifications/initialized", "ping", "tools/list"]) {
      expect(isPublicMcpRequest(rpc(m))).toBe(true);
    }
  });

  it("refuses every tool call", () => {
    expect(isPublicMcpRequest(rpc("tools/call", { name: "get_account", arguments: {} }))).toBe(false);
  });

  it("refuses a batch that hides one tool call among public messages", () => {
    expect(isPublicMcpRequest([INIT, rpc("tools/list", {}, 2), rpc("tools/call", { name: "scan_url" }, 3)])).toBe(false);
  });

  it("refuses anything that is not a JSON-RPC request", () => {
    for (const body of [undefined, null, "", {}, [], { id: 1, result: {} }, { method: 7 }]) {
      expect(isPublicMcpRequest(body)).toBe(false);
    }
  });
});

describe("POST /mcp without a token", () => {
  it("answers initialize, so a directory can connect", async () => {
    const res = await request(app).post("/mcp").set(HEADERS).send(INIT);
    expect(res.status).toBe(200);
    expect(payload(res).result.serverInfo.name).toBe("secscan");
  });

  it("lists all the tools, so a directory's health check passes", async () => {
    const res = await request(app).post("/mcp").set(HEADERS).send(rpc("tools/list"));
    expect(res.status).toBe(200);
    const names = payload(res).result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain("scan_url");
    expect(names).toContain("get_account");
    expect(names.length).toBeGreaterThanOrEqual(12);
  });

  it("refuses a tool call with 401 and a Bearer challenge", async () => {
    const res = await request(app)
      .post("/mcp")
      .set(HEADERS)
      .send(rpc("tools/call", { name: "scan_url", arguments: { url: "https://example.com" } }));
    expect(res.status).toBe(401);
    // The challenge names the realm and, for OAuth-capable clients, where the sign-in metadata is.
    expect(res.headers["www-authenticate"]).toContain('Bearer realm="secscan"');
    expect(res.headers["www-authenticate"]).toContain("/.well-known/oauth-protected-resource/api/mcp");
    expect(res.headers["www-authenticate"]).toContain("resource_metadata=");
  });

  it("refuses a tool call smuggled into a batch", async () => {
    const res = await request(app)
      .post("/mcp")
      .set(HEADERS)
      .send([rpc("tools/list", {}, 1), rpc("tools/call", { name: "get_account", arguments: {} }, 2)]);
    expect(res.status).toBe(401);
  });
});

describe.skipIf(!TEST_DATABASE_URL)("POST /mcp tool calls, with real tokens (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let tokens: typeof import("../lib/apiTokens");
  let userId: string;
  let email: string;
  let mcpToken: string;
  let apiToken: string;

  async function issue(scope: "mcp" | "api") {
    const g = tokens.generateToken();
    await dbMod.db.insert(dbMod.apiTokensTable).values({ userId, name: `t-${scope}`, tokenHash: g.hash, prefix: g.prefix, scope });
    return g.token;
  }

  beforeAll(async () => {
    dbMod = await openDb();
    tokens = await import("../lib/apiTokens");
    email = uniqueEmail("mcp");
    const [u] = await dbMod.db.insert(dbMod.usersTable).values({ email }).returning({ id: dbMod.usersTable.id });
    userId = u!.id;
    mcpToken = await issue("mcp");
    apiToken = await issue("api");
  }, 60_000);

  afterAll(async () => {
    const { eq } = await import("drizzle-orm");
    await dbMod.db.delete(dbMod.apiTokensTable).where(eq(dbMod.apiTokensTable.userId, userId));
    await dbMod.db.delete(dbMod.usersTable).where(eq(dbMod.usersTable.id, userId));
    await dbMod?.pool?.end?.();
  });

  const call = (token: string) =>
    request(app)
      .post("/mcp")
      .set({ ...HEADERS, Authorization: `Bearer ${token}` })
      .send(rpc("tools/call", { name: "get_account", arguments: {} }));

  it("refuses a tool call with a wrong token", async () => {
    expect((await call("ssk_wrong")).status).toBe(401);
  });

  it("refuses a token that was valid but has been revoked", async () => {
    const revoked = await issue("mcp");
    const { eq } = await import("drizzle-orm");
    await dbMod.db.update(dbMod.apiTokensTable).set({ revokedAt: new Date() }).where(eq(dbMod.apiTokensTable.tokenHash, tokens.hashToken(revoked)));
    expect((await call(revoked)).status).toBe(401);
  });

  it("refuses an API-scope token: it opens the REST API, not MCP", async () => {
    expect((await call(apiToken)).status).toBe(401);
  });

  it("answers a tool call for a real MCP token, as that token's user", async () => {
    const res = await call(mcpToken);
    expect(res.status).toBe(200);
    const result = payload(res).result;
    expect(result.isError).not.toBe(true);
    // The account tool reports this user's allowance (a brand-new user has all three free scans).
    expect(result.content[0].text).toMatch(/free scans?/i);
  });
});

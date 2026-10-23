/**
 * API tokens against a REAL Postgres: the lookup is a join and a revocation
 * predicate, which a mocked db would "pass" regardless. Skips unless a
 * throwaway database is supplied — see billing.integration.test.ts.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const URL_ = process.env["BILLING_TEST_DATABASE_URL"];
const suite = URL_ ? describe : describe.skip;
if (URL_) process.env["DATABASE_URL"] = URL_;

suite("API tokens (real Postgres)", () => {
  let dbMod: typeof import("@workspace/db");
  let tokens: typeof import("./apiTokens");

  beforeAll(async () => {
    dbMod = await import("@workspace/db");
    await dbMod.migrateToLatest(URL_!);
    tokens = await import("./apiTokens");
  }, 60_000);
  afterAll(async () => { await dbMod?.pool?.end?.(); });

  async function userWithToken(email: string | null) {
    const { db, usersTable, apiTokensTable } = dbMod;
    const [u] = await db.insert(usersTable).values({ email }).returning({ id: usersTable.id });
    const g = tokens.generateToken();
    const [t] = await db.insert(apiTokensTable).values({ userId: u!.id, name: "t", tokenHash: g.hash, prefix: g.prefix }).returning({ id: apiTokensTable.id });
    return { userId: u!.id, tokenId: t!.id, token: g.token };
  }

  it("resolves a live token to its registered owner", async () => {
    const { userId, token } = await userWithToken(`tok-${Date.now()}@example.com`);
    const user = await tokens.authenticateApiToken(`Bearer ${token}`);
    expect(user?.id).toBe(userId);
  });

  it("refuses a revoked token", async () => {
    const { tokenId, token } = await userWithToken(`tok-rev-${Date.now()}@example.com`);
    const { db, apiTokensTable } = dbMod;
    const { eq } = await import("drizzle-orm");
    await db.update(apiTokensTable).set({ revokedAt: new Date() }).where(eq(apiTokensTable.id, tokenId));
    expect(await tokens.authenticateApiToken(`Bearer ${token}`)).toBeNull();
  });

  it("refuses a token belonging to an identity with no registered email", async () => {
    const { token } = await userWithToken(null);
    expect(await tokens.authenticateApiToken(`Bearer ${token}`)).toBeNull();
  });

  it("a token carries one scope: an mcp token is refused by the API and an api token by MCP", async () => {
    const { db, usersTable, apiTokensTable } = dbMod;
    const [u] = await db.insert(usersTable).values({ email: `tok-scope-${Date.now()}@example.com` }).returning({ id: usersTable.id });
    const mcp = tokens.generateToken();
    const api = tokens.generateToken();
    await db.insert(apiTokensTable).values([
      { userId: u!.id, name: "editor", tokenHash: mcp.hash, prefix: mcp.prefix }, // scope defaults to mcp
      { userId: u!.id, name: "ci", tokenHash: api.hash, prefix: api.prefix, scope: "api" },
    ]);

    expect((await tokens.authenticateApiToken(`Bearer ${mcp.token}`))?.id).toBe(u!.id);
    expect((await tokens.authenticateApiToken(`Bearer ${mcp.token}`, "mcp"))?.id).toBe(u!.id);
    expect(await tokens.authenticateApiToken(`Bearer ${mcp.token}`, "api")).toBeNull();

    expect((await tokens.authenticateApiToken(`Bearer ${api.token}`, "api"))?.id).toBe(u!.id);
    expect(await tokens.authenticateApiToken(`Bearer ${api.token}`)).toBeNull();
    expect(await tokens.authenticateApiToken(`Bearer ${api.token}`, "mcp")).toBeNull();
  });

  it("refuses a well-formed token that was never issued", async () => {
    expect(await tokens.authenticateApiToken(`Bearer ${tokens.generateToken().token}`)).toBeNull();
  });
});

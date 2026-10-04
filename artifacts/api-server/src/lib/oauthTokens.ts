/**
 * The OAuth token lifecycle: authorization codes, access and refresh tokens, revoking.
 *
 * Access tokens are ordinary api_tokens rows (scope "mcp") with an expiry, so the
 * MCP endpoint authenticates them exactly as it does a pasted token. That means an
 * OAuth token can never do anything a pasted MCP token could not.
 *
 * Every state change that must happen once is ONE statement (UPDATE … WHERE
 * used_at IS NULL RETURNING), never read-then-write: two racing requests with the
 * same code or refresh token cannot both succeed.
 *
 * Replay is treated as theft. A code presented twice, or a refresh token presented
 * after it was already used, revokes every token in that family: whoever holds the
 * copy that is now stale is either the thief or the victim, and the person can sign
 * in again in seconds.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { db, apiTokensTable, oauthClientsTable, oauthCodesTable, oauthRefreshTokensTable } from "@workspace/db";
import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { generateToken } from "./apiTokens";
import { verifyPkce } from "./oauthPkce";

export const CODE_TTL_MS = 10 * 60_000;
export const ACCESS_TTL_MS = 60 * 60_000;
export const REFRESH_TTL_MS = 30 * 24 * 60 * 60_000;

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const secret = () => randomBytes(32).toString("base64url");

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: "mcp";
}
export type OAuthResult = { ok: true; tokens: TokenResponse } | { ok: false; error: "invalid_grant"; description: string };
const denied = (description: string): OAuthResult => ({ ok: false, error: "invalid_grant", description });

type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];

export async function issueAuthorizationCode(input: { userId: string; clientId: string; redirectUri: string; codeChallenge: string }): Promise<string> {
  const code = secret();
  await db.insert(oauthCodesTable).values({
    codeHash: sha256(code),
    clientId: input.clientId,
    userId: input.userId,
    redirectUri: input.redirectUri,
    codeChallenge: input.codeChallenge,
    familyId: randomUUID(),
    expiresAt: new Date(Date.now() + CODE_TTL_MS),
  });
  return code;
}

async function revokeFamily(tx: Tx | typeof db, familyId: string): Promise<void> {
  const now = new Date();
  await tx.update(apiTokensTable).set({ revokedAt: now }).where(and(eq(apiTokensTable.oauthFamilyId, familyId), isNull(apiTokensTable.revokedAt)));
  await tx.update(oauthRefreshTokensTable).set({ revokedAt: now }).where(and(eq(oauthRefreshTokensTable.familyId, familyId), isNull(oauthRefreshTokensTable.revokedAt)));
}

async function issuePair(tx: Tx, input: { userId: string; clientId: string; familyId: string }): Promise<TokenResponse> {
  const [client] = await tx.select({ name: oauthClientsTable.name }).from(oauthClientsTable).where(eq(oauthClientsTable.clientId, input.clientId)).limit(1);
  const access = generateToken();
  await tx.insert(apiTokensTable).values({
    userId: input.userId,
    name: `OAuth: ${client?.name ?? "app"}`.slice(0, 60),
    tokenHash: access.hash,
    prefix: access.prefix,
    scope: "mcp",
    expiresAt: new Date(Date.now() + ACCESS_TTL_MS),
    oauthClientId: input.clientId,
    oauthFamilyId: input.familyId,
  });
  const refresh = secret();
  await tx.insert(oauthRefreshTokensTable).values({
    tokenHash: sha256(refresh),
    clientId: input.clientId,
    userId: input.userId,
    familyId: input.familyId,
    expiresAt: new Date(Date.now() + REFRESH_TTL_MS),
  });
  await tx.update(oauthClientsTable).set({ lastUsedAt: new Date() }).where(eq(oauthClientsTable.clientId, input.clientId));
  return { access_token: access.token, token_type: "Bearer", expires_in: ACCESS_TTL_MS / 1000, refresh_token: refresh, scope: "mcp" };
}

/** Trade a one-time code (plus the PKCE verifier) for tokens. */
export async function exchangeCode(input: { code: unknown; clientId: unknown; redirectUri: unknown; codeVerifier: unknown }): Promise<OAuthResult> {
  if (typeof input.code !== "string" || input.code.length < 20 || input.code.length > 200) return denied("The code is invalid or expired.");
  const codeHash = sha256(input.code);

  return db.transaction(async (tx) => {
    const [claimed] = await tx
      .update(oauthCodesTable)
      .set({ usedAt: new Date() })
      .where(and(eq(oauthCodesTable.codeHash, codeHash), isNull(oauthCodesTable.usedAt), gt(oauthCodesTable.expiresAt, new Date())))
      .returning();

    if (!claimed) {
      // Already used: someone is replaying it. Take back everything it produced.
      const [seen] = await tx.select({ familyId: oauthCodesTable.familyId, usedAt: oauthCodesTable.usedAt }).from(oauthCodesTable).where(eq(oauthCodesTable.codeHash, codeHash)).limit(1);
      if (seen?.usedAt) await revokeFamily(tx, seen.familyId);
      return denied("The code is invalid or expired.");
    }
    // The code is spent from here on, whatever else is wrong with the request.
    if (claimed.clientId !== input.clientId) return denied("The code was issued to a different app.");
    if (claimed.redirectUri !== input.redirectUri) return denied("redirect_uri does not match the authorization request.");
    if (!verifyPkce(input.codeVerifier, claimed.codeChallenge)) return denied("code_verifier does not match.");

    return { ok: true as const, tokens: await issuePair(tx, { userId: claimed.userId, clientId: claimed.clientId, familyId: claimed.familyId }) };
  });
}

/** Trade a refresh token for a new pair. The old refresh token and the old access token stop working. */
export async function refreshTokens(input: { refreshToken: unknown; clientId: unknown }): Promise<OAuthResult> {
  if (typeof input.refreshToken !== "string" || input.refreshToken.length < 20 || input.refreshToken.length > 200) return denied("The refresh token is invalid or expired.");
  const tokenHash = sha256(input.refreshToken);

  return db.transaction(async (tx) => {
    const [claimed] = await tx
      .update(oauthRefreshTokensTable)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(oauthRefreshTokensTable.tokenHash, tokenHash),
          isNull(oauthRefreshTokensTable.usedAt),
          isNull(oauthRefreshTokensTable.revokedAt),
          gt(oauthRefreshTokensTable.expiresAt, new Date()),
        ),
      )
      .returning();

    if (!claimed) {
      const [seen] = await tx.select({ familyId: oauthRefreshTokensTable.familyId, usedAt: oauthRefreshTokensTable.usedAt }).from(oauthRefreshTokensTable).where(eq(oauthRefreshTokensTable.tokenHash, tokenHash)).limit(1);
      if (seen?.usedAt) await revokeFamily(tx, seen.familyId);
      return denied("The refresh token is invalid or expired.");
    }
    if (claimed.clientId !== input.clientId) {
      // A token presented by another app: burn the family, it has leaked.
      await revokeFamily(tx, claimed.familyId);
      return denied("The refresh token was issued to a different app.");
    }

    // Only the newest access token stays live.
    await tx.update(apiTokensTable).set({ revokedAt: new Date() }).where(and(eq(apiTokensTable.oauthFamilyId, claimed.familyId), isNull(apiTokensTable.revokedAt)));
    return { ok: true as const, tokens: await issuePair(tx, { userId: claimed.userId, clientId: claimed.clientId, familyId: claimed.familyId }) };
  });
}

/** RFC 7009: revoke by token. Always succeeds from the caller's point of view; it never says whether the token existed. */
export async function revokeByToken(token: unknown): Promise<void> {
  if (typeof token !== "string" || token.length < 20 || token.length > 200) return;
  const hash = sha256(token);
  const [refresh] = await db.select({ familyId: oauthRefreshTokensTable.familyId }).from(oauthRefreshTokensTable).where(eq(oauthRefreshTokensTable.tokenHash, hash)).limit(1);
  if (refresh) return revokeFamily(db, refresh.familyId);
  const [access] = await db.select({ familyId: apiTokensTable.oauthFamilyId }).from(apiTokensTable).where(eq(apiTokensTable.tokenHash, hash)).limit(1);
  if (access?.familyId) await revokeFamily(db, access.familyId);
}

/** Disconnect an app from an account: every token it holds, refresh tokens included. */
export async function disconnectApp(userId: string, clientId: string): Promise<number> {
  const now = new Date();
  const revoked = await db
    .update(apiTokensTable)
    .set({ revokedAt: now })
    .where(and(eq(apiTokensTable.userId, userId), eq(apiTokensTable.oauthClientId, clientId), isNull(apiTokensTable.revokedAt)))
    .returning({ id: apiTokensTable.id });
  await db
    .update(oauthRefreshTokensTable)
    .set({ revokedAt: now })
    .where(and(eq(oauthRefreshTokensTable.userId, userId), eq(oauthRefreshTokensTable.clientId, clientId), isNull(oauthRefreshTokensTable.revokedAt)));
  return revoked.length;
}

/**
 * Revoke everything an account has handed out: every API token, every connected app's access
 * token and every refresh token. For a password reset, where whoever held the old password may
 * have minted a token or connected an app that would otherwise outlive the reset.
 */
export async function revokeAllAccess(userId: string): Promise<void> {
  const now = new Date();
  await db
    .update(apiTokensTable)
    .set({ revokedAt: now })
    .where(and(eq(apiTokensTable.userId, userId), isNull(apiTokensTable.revokedAt)));
  await db
    .update(oauthRefreshTokensTable)
    .set({ revokedAt: now })
    .where(and(eq(oauthRefreshTokensTable.userId, userId), isNull(oauthRefreshTokensTable.revokedAt)));
}

export interface Connection {
  clientId: string;
  name: string;
  connectedAt: Date;
  lastUsedAt: Date | null;
}

/** The apps this person has connected and not disconnected: those still holding a live refresh token. */
export async function listConnections(userId: string): Promise<Connection[]> {
  const rows = await db
    .select({
      clientId: oauthClientsTable.clientId,
      name: oauthClientsTable.name,
      connectedAt: sql<Date>`min(${oauthRefreshTokensTable.createdAt})`,
      lastUsedAt: oauthClientsTable.lastUsedAt,
    })
    .from(oauthRefreshTokensTable)
    .innerJoin(oauthClientsTable, eq(oauthClientsTable.clientId, oauthRefreshTokensTable.clientId))
    .where(and(eq(oauthRefreshTokensTable.userId, userId), isNull(oauthRefreshTokensTable.revokedAt), gt(oauthRefreshTokensTable.expiresAt, new Date())))
    .groupBy(oauthClientsTable.clientId, oauthClientsTable.name, oauthClientsTable.lastUsedAt);
  return rows.map((r) => ({ ...r, connectedAt: new Date(r.connectedAt) }));
}

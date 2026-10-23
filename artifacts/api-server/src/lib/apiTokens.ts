/**
 * Personal API tokens for the MCP endpoint.
 *
 * Format: "ssk_" + 32 random bytes, base64url (43 chars) — 256 bits, so a
 * token cannot be guessed, and the prefix makes one recognisable in a leaked
 * config file or a secret scanner. Only the SHA-256 is stored. A plain hash
 * (no salt, no slow KDF) is correct here and not for passwords: the input is
 * already uniformly random at full strength, so there is nothing for a slow
 * hash to protect, and lookups must be a single indexed equality.
 *
 * A token has ONE scope. "mcp" authenticates routes/mcp.ts only; "api" authenticates
 * the REST API (routes/v1.ts) only. Neither can reach an account route, mint or
 * revoke tokens, or the other's endpoint, so a token leaked from an editor config
 * cannot drive CI, and one leaked from CI cannot be pointed at an editor. See
 * api_tokens in the schema.
 */
import { createHash, randomBytes } from "node:crypto";
import { db, apiTokensTable, usersTable } from "@workspace/db";
import { and, eq, gt, isNull, count, or } from "drizzle-orm";

export const TOKEN_PREFIX = "ssk_";

export type TokenScope = "mcp" | "api";
export const TOKEN_SCOPES: readonly TokenScope[] = ["mcp", "api"];
/** Enough for a few editors and machines; a cap keeps a leaked session from minting hundreds. */
export const MAX_TOKENS_PER_USER = 10;
/** last_used_at is refreshed at most this often, so a busy editor is not a write per request. */
const LAST_USED_REFRESH_MS = 5 * 60_000;

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function generateToken(): { token: string; hash: string; prefix: string } {
  const token = TOKEN_PREFIX + randomBytes(32).toString("base64url");
  return { token, hash: hashToken(token), prefix: token.slice(0, 10) };
}

export interface TokenUser {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  profileImageUrl: string | null;
}

/**
 * Resolve an `Authorization: Bearer ssk_…` header to its user, or null.
 *
 * Refuses revoked tokens, and users without an email — a token must belong to
 * a real account, for the same reason checkout refuses legacy anonymous
 * identities (routes/checkout.ts).
 */
export async function authenticateApiToken(authorization: string | undefined, scope: TokenScope = "mcp"): Promise<TokenUser | null> {
  if (!authorization?.startsWith("Bearer ")) return null;
  const token = authorization.slice(7).trim();
  if (!token.startsWith(TOKEN_PREFIX) || token.length < 20 || token.length > 200) return null;

  const [row] = await db
    .select({
      tokenId: apiTokensTable.id,
      tokenScope: apiTokensTable.scope,
      lastUsedAt: apiTokensTable.lastUsedAt,
      id: usersTable.id,
      email: usersTable.email,
      firstName: usersTable.firstName,
      lastName: usersTable.lastName,
      profileImageUrl: usersTable.profileImageUrl,
    })
    .from(apiTokensTable)
    .innerJoin(usersTable, eq(usersTable.id, apiTokensTable.userId))
    // An expired token (an OAuth access token after its hour) is refused like an unknown one.
    .where(and(eq(apiTokensTable.tokenHash, hashToken(token)), isNull(apiTokensTable.revokedAt), or(isNull(apiTokensTable.expiresAt), gt(apiTokensTable.expiresAt, new Date()))))
    .limit(1);

  if (!row || !row.email) return null;
  // A valid token used on the wrong surface is refused exactly like an unknown one.
  if (row.tokenScope !== scope) return null;

  if (!row.lastUsedAt || Date.now() - row.lastUsedAt.getTime() > LAST_USED_REFRESH_MS) {
    // Best effort: "last used" is a convenience for spotting stale tokens, and
    // must never fail the request it describes.
    void db
      .update(apiTokensTable)
      .set({ lastUsedAt: new Date() })
      .where(eq(apiTokensTable.id, row.tokenId))
      .catch(() => {});
  }

  return {
    id: row.id,
    email: row.email,
    firstName: row.firstName,
    lastName: row.lastName,
    profileImageUrl: row.profileImageUrl,
  };
}

export async function liveTokenCount(userId: string): Promise<number> {
  const [row] = await db
    .select({ n: count() })
    .from(apiTokensTable)
    // Pasted tokens only: apps connected by OAuth are listed and limited separately.
    .where(and(eq(apiTokensTable.userId, userId), isNull(apiTokensTable.revokedAt), isNull(apiTokensTable.oauthClientId)));
  return row?.n ?? 0;
}

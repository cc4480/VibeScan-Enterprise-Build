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
 * These authenticate routes/mcp.ts ONLY. See api_tokens in the schema for why.
 */
import { createHash, randomBytes } from "node:crypto";
import { db, apiTokensTable, usersTable } from "@workspace/db";
import { and, eq, isNull, count } from "drizzle-orm";

export const TOKEN_PREFIX = "ssk_";
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
export async function authenticateApiToken(authorization: string | undefined): Promise<TokenUser | null> {
  if (!authorization?.startsWith("Bearer ")) return null;
  const token = authorization.slice(7).trim();
  if (!token.startsWith(TOKEN_PREFIX) || token.length < 20 || token.length > 200) return null;

  const [row] = await db
    .select({
      tokenId: apiTokensTable.id,
      lastUsedAt: apiTokensTable.lastUsedAt,
      id: usersTable.id,
      email: usersTable.email,
      firstName: usersTable.firstName,
      lastName: usersTable.lastName,
      profileImageUrl: usersTable.profileImageUrl,
    })
    .from(apiTokensTable)
    .innerJoin(usersTable, eq(usersTable.id, apiTokensTable.userId))
    .where(and(eq(apiTokensTable.tokenHash, hashToken(token)), isNull(apiTokensTable.revokedAt)))
    .limit(1);

  if (!row || !row.email) return null;

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
    .where(and(eq(apiTokensTable.userId, userId), isNull(apiTokensTable.revokedAt)));
  return row?.n ?? 0;
}

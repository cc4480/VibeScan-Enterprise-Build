import { pgTable, text, uuid, timestamp, jsonb, index } from "drizzle-orm/pg-core";

/**
 * OAuth 2.1 for the MCP endpoint (an editor connects with a browser sign-in instead
 * of a pasted token). See lib/oauth*.ts.
 *
 * Nothing secret is stored in the clear: authorization codes and refresh tokens are
 * kept as SHA-256 hashes, like API tokens. Access tokens are ordinary api_tokens rows
 * (scope "mcp") with an expiry, so MCP authentication is unchanged.
 */

/** Apps that registered themselves (RFC 7591). Public clients: no secret, PKCE is the proof. */
export const oauthClientsTable = pgTable("oauth_clients", {
  clientId: text("client_id").primaryKey(),
  name: text("name").notNull(),
  redirectUris: jsonb("redirect_uris").$type<string[]>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
});

/** One-time codes handed back to the app's redirect URI. Ten minutes, single use, bound to the PKCE challenge. */
export const oauthCodesTable = pgTable("oauth_codes", {
  codeHash: text("code_hash").primaryKey(),
  clientId: text("client_id").notNull(),
  userId: text("user_id").notNull(),
  redirectUri: text("redirect_uri").notNull(),
  codeChallenge: text("code_challenge").notNull(),
  /** The family every token issued from this code belongs to, so replaying the code can revoke them. */
  familyId: uuid("family_id").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  usedAt: timestamp("used_at", { withTimezone: true }),
});

/** Refresh tokens rotate on every use; presenting a used one revokes the whole family. */
export const oauthRefreshTokensTable = pgTable("oauth_refresh_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  tokenHash: text("token_hash").notNull().unique(),
  clientId: text("client_id").notNull(),
  userId: text("user_id").notNull(),
  familyId: uuid("family_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  usedAt: timestamp("used_at", { withTimezone: true }),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (table) => [
  index("idx_oauth_refresh_family").on(table.familyId),
  index("idx_oauth_refresh_user").on(table.userId),
]);

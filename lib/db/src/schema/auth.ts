import { sql } from "drizzle-orm";
import { index, jsonb, pgTable, timestamp, varchar } from "drizzle-orm/pg-core";

// (IMPORTANT) This table is mandatory for Replit Auth, don't drop it.
export const sessionsTable = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// (IMPORTANT) This table is mandatory for Replit Auth, don't drop it.
export const usersTable = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  // User-supplied DeepSeek API key, AES-256-GCM encrypted at rest (see
  // artifacts/api-server/src/lib/crypto.ts). Never decrypted for API responses —
  // only deepseekApiKeyLast4 is ever sent to the client, for display purposes.
  deepseekApiKeyEncrypted: varchar("deepseek_api_key_encrypted"),
  deepseekApiKeyLast4: varchar("deepseek_api_key_last4", { length: 4 }),

  // ── Account credentials ────────────────────────────────────────────────────
  // Null for anonymous identities: a row whose id is the UUID the browser
  // generated and sends as a bearer token. Setting this promotes that same row
  // into a real account in place, so every scan, report and credit already
  // pointing at the id follows the user across without migrating any rows.
  //
  // It is also the flag that closes the bearer path: once a row has a password,
  // authMiddleware refuses to authenticate it from a bearer token, because the
  // UUID would otherwise stay a permanent password-equivalent credential for
  // the account. See middlewares/authMiddleware.ts.
  passwordHash: varchar("password_hash"),
  emailVerifiedAt: timestamp("email_verified_at", { withTimezone: true }),

  // Google's subject claim, for accounts that sign in with Google. Stored
  // rather than matching on email alone because a Google account's email can
  // change while `sub` never does — matching only on email would silently
  // follow the address to whoever holds it next.
  //
  // Note that a Google-only account has no password, so passwordHash cannot be
  // the thing that closes the bearer path for it. authMiddleware treats any row
  // with an email as a real account for that purpose.
  googleSub: varchar("google_sub").unique(),

  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

/**
 * Single-use tokens for email verification and password reset.
 *
 * Only the SHA-256 of the token is stored: the raw value goes out in an email
 * and never exists in the database, so a leaked table cannot be used to verify
 * an address or reset a password.
 */
export const authTokensTable = pgTable(
  "auth_tokens",
  {
    id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
    userId: varchar("user_id").notNull(),
    tokenHash: varchar("token_hash").notNull().unique(),
    purpose: varchar("purpose", { enum: ["email_verify", "password_reset"] }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    // Set when redeemed, rather than deleting the row, so a replayed link can
    // be told apart from one that never existed.
    usedAt: timestamp("used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("IDX_auth_tokens_user").on(table.userId)],
);

export type AuthToken = typeof authTokensTable.$inferSelect;

export type UpsertUser = typeof usersTable.$inferInsert;
export type User = typeof usersTable.$inferSelect;

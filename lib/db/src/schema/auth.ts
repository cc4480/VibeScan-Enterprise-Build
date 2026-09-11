import { sql } from "drizzle-orm";
import { index, integer, jsonb, pgTable, timestamp, varchar, boolean} from "drizzle-orm/pg-core";

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

  // Email preferences. Two flags rather than one, because the two kinds of mail
  // are opted out of for different reasons and by different routes: product
  // updates are marketing and are turned off in Settings, while monitor alerts
  // are mail the user asked for per target and are turned off from the
  // List-Unsubscribe header on the alert itself.
  //
  // Neither covers account mail — password resets, email verification and
  // purchase receipts still send, because switching those off would lock
  // people out of their own account.
  marketingOptedOut: boolean("marketing_opted_out").notNull().default(false),
  alertEmailsOptedOut: boolean("alert_emails_opted_out").notNull().default(false),

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

/**
 * A password login that has passed step one and is waiting for its emailed code.
 *
 * This is what makes the code a genuine SECOND factor rather than a second
 * delivery of the first. A row here is created ONLY after a password has been
 * verified, and a session is issued ONLY by redeeming one. Neither half signs
 * anyone in on its own: knowing the password gets you a row and an email you
 * cannot read, and holding the code is useless without a row to spend it on.
 *
 * A six-digit code is a far weaker secret than the 32-byte values in
 * auth_tokens — a million possibilities, walkable in seconds — so three things
 * carry it, and all three live in this table's shape:
 *
 *  - challengeHash scopes the lookup. A code is never matched on its own value;
 *    it is matched inside one challenge, which only someone who already passed
 *    the password step holds. Without this, a guess would be tested against
 *    every pending login at once instead of one.
 *  - attempts caps guessing. Five wrong tries and the row is spent, correct
 *    code or not.
 *  - expiresAt keeps the window small, and issuing a new challenge retires the
 *    user's earlier ones so several codes are never live at once.
 *
 * Only hashes are stored, as with auth_tokens: a dumped table yields neither a
 * usable code nor a usable challenge.
 */
export const pendingLoginsTable = pgTable(
  "pending_logins",
  {
    id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
    userId: varchar("user_id").notNull(),
    // SHA-256 of the opaque challenge handed to the client in step one.
    challengeHash: varchar("challenge_hash").notNull().unique(),
    // SHA-256 of the six-digit code emailed to the account's address.
    codeHash: varchar("code_hash").notNull(),
    attempts: integer("attempts").notNull().default(0),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    // Set when redeemed or abandoned, rather than deleting, so a replay can be
    // told apart from a challenge that never existed.
    usedAt: timestamp("used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("IDX_pending_logins_user").on(table.userId)],
);

export type PendingLogin = typeof pendingLoginsTable.$inferSelect;

/**
 * Addresses we must stop mailing, fed by Resend's bounce and complaint webhooks.
 *
 * Repeatedly mailing a dead address, or someone who pressed "spam", is how
 * sender reputation erodes — and reputation is what decides whether the mail
 * people DO want lands in the inbox. Nothing was recording either signal, so
 * every bounce was invisible and every complaint was repeated.
 *
 * `scope` is the part that matters and is easy to get wrong:
 *
 *  - "all" — the address does not exist (a hard bounce). Sending anything to
 *    it is pointless and counts against us, so everything stops.
 *  - "bulk" — the person marked mail as spam. Marketing and alerts stop, but
 *    ACCOUNT mail does not: a sign-in code, a password reset or a receipt is
 *    something they just asked for by their own action, and suppressing those
 *    would lock someone out of their account as a side effect of a complaint
 *    about a newsletter. That is a worse outcome than the reputation cost.
 *
 * Soft bounces (mailbox full, temporary failure) deliberately do NOT land here.
 * They resolve on their own, and suppressing on one would quietly cut off a
 * real user whose inbox was briefly over quota.
 */
export const emailSuppressionsTable = pgTable(
  "email_suppressions",
  {
    // Lower-cased address. The natural key, so a repeat webhook for the same
    // address updates rather than accumulating rows.
    email: varchar("email").primaryKey(),
    scope: varchar("scope", { enum: ["all", "bulk"] }).notNull(),
    reason: varchar("reason", { enum: ["hard_bounce", "complaint", "manual"] }).notNull(),
    // The provider's own description, kept for when someone asks why they
    // stopped receiving mail.
    detail: varchar("detail"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
  },
  (table) => [index("IDX_email_suppressions_scope").on(table.scope)],
);

export type EmailSuppression = typeof emailSuppressionsTable.$inferSelect;

export type AuthToken = typeof authTokensTable.$inferSelect;

export type UpsertUser = typeof usersTable.$inferInsert;
export type User = typeof usersTable.$inferSelect;

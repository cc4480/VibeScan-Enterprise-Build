/** Billing tables: credits, purchase intents, subscriptions, Stripe events and API tokens. */
import { pgTable, text, uuid, integer, timestamp, index, uniqueIndex, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";

export const creditsTable = pgTable("credits", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull().unique(),
  balance: integer("balance").notNull().default(0),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/**
 * Someone who ran out of free scans and said they would pay.
 *
 * There is no checkout yet, so the free-scan cap is currently a wall with
 * nothing behind it: a person who likes the product enough to spend every free
 * scan hits a message telling them to come back later, and leaves without
 * trace. This table is what turns that dead end into the one measurement worth
 * having before building billing — how many people actually wanted to pay.
 *
 * One row per user, so pressing the button twice is not two signals. Delete
 * this table, and the route that writes it, when Checkout Session creation
 * ships and the cap stops being a wall.
 */
export const purchaseIntentsTable = pgTable("purchase_intents", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull().unique(),
  // Copied rather than joined, because it is what we would actually mail, and
  // a user changing their address later should not silently retarget a signal
  // recorded against the old one.
  email: text("email").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  // When the "you can buy now" email went out. Set per row as each send
  // succeeds, so the launch mailer can be re-run after a partial failure
  // without emailing anyone twice. Null = promised, not yet told.
  notifiedAt: timestamp("notified_at", { withTimezone: true }),
});

export type PurchaseIntent = typeof purchaseIntentsTable.$inferSelect;

/**
 * What a user is entitled to, as distinct from what they are monitoring.
 *
 * One row per USER. `monitor_subscriptions` stays one row per monitored URL,
 * and this is the plan those rows live under — so "how many URLs may they
 * watch" and "may we still scan for them" are answered in one place instead of
 * being inferred from payment history at every call site.
 *
 * `urlLimit` is stored rather than derived from `plan` on purpose. Grandfathered
 * accounts and one-off arrangements then need no special case in code, and
 * changing a published tier's allowance later does not silently rewrite what an
 * existing customer was sold.
 *
 * `currentPeriodEnd` is null for rows that do not renew — grandfathered
 * accounts have no billing period to end.
 */
export const billingSubscriptionsTable = pgTable("billing_subscriptions", {
  id: uuid("id").primaryKey().defaultRandom(),
  // Unique: a user has at most one plan. A second row would make "which limit
  // applies" ambiguous at exactly the moment it matters.
  userId: text("user_id").notNull().unique(),
  // "unlimited" ($19/month: unlimited scans + 3 sites) is the one plan sold today;
  // lib/plans.ts holds the numbers. "starter" ($19: 3 sites + 20 scans) and "pro" ($49:
  // 5 sites + 100 scans) were sold until 2026-10-03 and are kept so a row carrying one
  // still resolves. solo/studio/agency were designed but never sold; kept in the enum so
  // no historical row can fail to parse. A plain text column: the list is TypeScript-only,
  // so adding a value needs no migration.
  plan: text("plan", { enum: ["unlimited", "starter", "pro", "solo", "studio", "agency", "grandfathered"] }).notNull(),
  // past_due is deliberately distinct from paused: Stripe is still retrying the
  // card, so access continues through the grace window. paused is the state
  // after that window, where scanning stops but history stays readable.
  status: text("status", {
    enum: ["active", "past_due", "paused", "cancelled"],
  }).notNull().default("active"),
  urlLimit: integer("url_limit").notNull(),
  currentPeriodEnd: timestamp("current_period_end", { withTimezone: true }),
  // Scans the plan includes, remaining in the current billing period. Reset to
  // the plan's allowance on every paid invoice — not incremented — so unused
  // scans do not roll over and a redelivered invoice.paid cannot stack them.
  includedScansRemaining: integer("included_scans_remaining").notNull().default(0),
  grandfathered: boolean("grandfathered").notNull().default(false),
  stripeCustomerId: text("stripe_customer_id"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_billing_sub_user_id").on(table.userId),
  index("idx_billing_sub_status").on(table.status),
  uniqueIndex("uq_billing_sub_stripe_sub").on(table.stripeSubscriptionId),
]);

/**
 * Stripe events already applied — the idempotency ledger for the webhook.
 *
 * Stripe delivers every event at least once, and redelivers on any slow or
 * failed acknowledgement. Without this, a redelivered checkout.session.completed
 * credited the account a second time. The webhook inserts the event id here in
 * the SAME transaction as the effect it applies: a duplicate hits the primary
 * key and applies nothing, and a failure part-way rolls back both, so the
 * retry is applied exactly once.
 */
export const stripeEventsTable = pgTable("stripe_events", {
  id: text("id").primaryKey(),
  type: text("type").notNull(),
  processedAt: timestamp("processed_at", { withTimezone: true }).notNull().defaultNow(),
});

/**
 * Personal API tokens — how an AI editor (Claude Code, Cursor, …) reaches the
 * MCP endpoint on a user's behalf, since it cannot hold a browser session.
 *
 * Only a SHA-256 of the token is stored; the token itself is shown once, at
 * creation. `prefix` is the first characters, kept so the UI can tell tokens
 * apart ("ssk_4fQ…") without being able to reconstruct one.
 *
 * Deliberately narrow: these authenticate the MCP endpoint and nothing else
 * (routes/mcp.ts). The site's own auth middleware never accepts them, so a
 * leaked token can start scans and read reports, but cannot delete the
 * account, buy anything, change the password or mint more tokens.
 */
export const apiTokensTable = pgTable("api_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  name: text("name").notNull(),
  tokenHash: text("token_hash").notNull().unique(),
  prefix: text("prefix").notNull(),
  // What the token may reach. "mcp" reaches only the MCP endpoint (every token before
  // this column); "api" reaches only the REST API under /api/v1. Never both: a token
  // pasted into an editor config should not also be able to drive CI, and the reverse.
  scope: text("scope", { enum: ["mcp", "api"] }).notNull().default("mcp"),
  // Set for tokens minted by the OAuth flow (lib/oauthTokens.ts): they expire, belong to an app
  // and a family (so replaying a refresh token revokes them all), and are listed under
  // "Connected apps", not as pasted tokens. Null for tokens the user created by hand.
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  oauthClientId: text("oauth_client_id"),
  oauthFamilyId: uuid("oauth_family_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (table) => [
  index("idx_api_tokens_user").on(table.userId),
]);

export const insertCreditSchema = createInsertSchema(creditsTable).omit({
  id: true,
  updatedAt: true,
});

export type InsertCredit = typeof creditsTable.$inferInsert;

export type Credit = typeof creditsTable.$inferSelect;

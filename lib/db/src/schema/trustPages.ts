import { pgTable, text, uuid, boolean, timestamp, uniqueIndex, index } from "drizzle-orm/pg-core";

/**
 * A public trust page for a domain an account has verified: the latest grade and scan date, in the owner's name and colour.
 *
 * Opt-in, one per domain (the domain is the page's address, /trust/<domain>), and only for a domain the account has
 * verified. Nothing here is a copy of any scan result: the page reads the account's latest verified scan of the domain when
 * it is requested, so it cannot drift from the report, and it stops showing the moment the verification lapses or the page
 * is turned off.
 */
export const trustPagesTable = pgTable("trust_pages", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  /** The registrable hostname, lower case, as the domain verification stores it. */
  domain: text("domain").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  /** The organisation name shown at the top. Plain text, bounded. */
  displayName: text("display_name"),
  /** A #rrggbb accent colour, validated before it is stored and again before it is used. */
  accent: text("accent"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  uniqueIndex("idx_trust_pages_domain").on(table.domain),
  index("idx_trust_pages_user").on(table.userId),
]);

export type TrustPage = typeof trustPagesTable.$inferSelect;

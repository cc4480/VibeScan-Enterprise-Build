import { pgTable, text, uuid, boolean, timestamp, index, uniqueIndex, primaryKey } from "drizzle-orm/pg-core";

/**
 * Where an account files findings as tickets in Linear or Jira: one destination per provider per account. The credential
 * (a Linear API key, or a Jira API token) is stored encrypted (lib/crypto.ts, the same key as stored scan logins), decrypted
 * only to make a call, and never returned to the browser.
 *
 * `target` is the Linear team key or the Jira project key. Jira also needs the site (acme.atlassian.net), the email the API
 * token belongs to and the issue type; Linear needs the team's id, looked up when the destination is saved.
 */
export const ticketDestinationsTable = pgTable("ticket_destinations", {
  userId: text("user_id").notNull(),
  provider: text("provider", { enum: ["linear", "jira"] }).notNull(),
  target: text("target").notNull(),
  site: text("site"),
  accountEmail: text("account_email"),
  issueType: text("issue_type"),
  externalId: text("external_id"),
  credentialEncrypted: text("credential_encrypted").notNull(),
  /** File tickets by itself when monitoring finds a new problem. Off until the account turns it on. */
  autoFile: boolean("auto_file").notNull().default(false),
  /** The lowest severity filed by itself. */
  autoMinSeverity: text("auto_min_severity", { enum: ["critical", "high", "medium"] }).notNull().default("high"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  primaryKey({ columns: [table.userId, table.provider] }),
]);

/**
 * The tickets already filed, so the same finding on the same site is not filed twice in the same place. `findingKey` is a hash
 * of the site and the finding's name, not of the report (the next scan finds the same problem under a new id).
 * `destination` names where it went (the team key, or site and project key), so pointing the account elsewhere starts afresh.
 */
export const ticketsTable = pgTable("tickets", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  provider: text("provider", { enum: ["linear", "jira"] }).notNull(),
  destination: text("destination").notNull(),
  findingKey: text("finding_key").notNull(),
  /** The report the ticket was first filed from. */
  reportId: uuid("report_id"),
  /** ENG-12, or SEC-7. */
  ticketKey: text("ticket_key").notNull(),
  ticketUrl: text("ticket_url").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  uniqueIndex("idx_tickets_user_provider_dest_finding").on(table.userId, table.provider, table.destination, table.findingKey),
  index("idx_tickets_report").on(table.reportId),
]);

export type Ticket = typeof ticketsTable.$inferSelect;
export type TicketDestination = typeof ticketDestinationsTable.$inferSelect;

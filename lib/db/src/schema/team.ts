import { pgTable, text, uuid, timestamp, uniqueIndex, index } from "drizzle-orm/pg-core";

/**
 * Teammates an account has invited to read its reports.
 *
 * `userId` is the account that owns the reports and sent the invitation (named user_id like every account-owned table, so
 * the account-deletion guard covers it); `memberId` is the teammate once they have accepted. A row is pending until the
 * invited person, signed in with the invited address, redeems the invitation token; only a hash of the token is stored.
 * Removing a row ends the access at once: reads check this table on every request.
 */
export const teamMembersTable = pgTable("team_members", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  memberId: text("member_id"),
  /** Lower case. The address the invitation was sent to, and the only address that may accept it. */
  invitedEmail: text("invited_email").notNull(),
  /** SHA-256 of the invitation token; cleared when the invitation is accepted. */
  tokenHash: text("token_hash"),
  status: text("status", { enum: ["pending", "active"] }).notNull().default("pending"),
  /** viewer reads; editor can also pause and resume the owner's monitors and file tickets from the owner's reports (lib/team.ts). Never more. */
  role: text("role", { enum: ["viewer", "editor"] }).notNull().default("viewer"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  acceptedAt: timestamp("accepted_at", { withTimezone: true }),
}, (table) => [
  uniqueIndex("idx_team_members_owner_email").on(table.userId, table.invitedEmail),
  uniqueIndex("idx_team_members_token").on(table.tokenHash),
  index("idx_team_members_member").on(table.memberId),
]);

export type TeamMember = typeof teamMembersTable.$inferSelect;

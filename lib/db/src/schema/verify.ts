import { pgTable, text, uuid, timestamp, index } from "drizzle-orm/pg-core";

/**
 * "I fixed this, check it": one row per request to re-check a single finding.
 * The check is an ordinary scan (origin "verify") whose report is judged against
 * the report that contained the finding, under the rule in lib/scanDiff.ts
 * (verdictFor): gone is only "fixed" if the test that raises it ran again.
 */
export const findingVerificationsTable = pgTable("finding_verifications", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  /** The report that contained the finding. */
  reportId: uuid("report_id").notNull(),
  /** The finding's id inside that report's stored data. */
  findingId: text("finding_id").notNull(),
  /** The scan that does the re-check. */
  scanId: uuid("scan_id").notNull(),
  verdict: text("verdict", { enum: ["pending", "fixed", "still_present", "not_rechecked", "failed"] }).notNull().default("pending"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
}, (table) => [
  index("idx_verifications_report").on(table.reportId),
  index("idx_verifications_scan").on(table.scanId),
  index("idx_verifications_user_created").on(table.userId, table.createdAt),
]);

import { pgTable, text, uuid, integer, boolean, timestamp, index, uniqueIndex } from "drizzle-orm/pg-core";

/**
 * Where an account files GitHub issues for findings: one repository, and a fine-grained personal access token that can
 * create issues in it. The token is stored encrypted (lib/crypto.ts, the same key as stored scan logins) and is only ever
 * decrypted to call GitHub; it is never returned to the browser. One destination per account.
 */
export const githubIssueDestinationsTable = pgTable("github_issue_destinations", {
  userId: text("user_id").primaryKey(),
  /** "owner/name". */
  repoFullName: text("repo_full_name").notNull(),
  tokenEncrypted: text("token_encrypted").notNull(),
  /** File issues by itself when monitoring finds a new problem. Off until the account turns it on. */
  autoFile: boolean("auto_file").notNull().default(false),
  /** The lowest severity filed by itself. */
  autoMinSeverity: text("auto_min_severity", { enum: ["critical", "high", "medium"] }).notNull().default("high"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/**
 * The issues already filed, so the same finding on the same site is not filed twice. `findingKey` is a hash of the site
 * and the finding's name, not of the report: the next scan finds the same problem under a new id, and it must still
 * find the issue that already exists.
 */
export const githubIssuesTable = pgTable("github_issues", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  repoFullName: text("repo_full_name").notNull(),
  findingKey: text("finding_key").notNull(),
  /** The report the issue was first filed from. */
  reportId: uuid("report_id"),
  issueNumber: integer("issue_number").notNull(),
  issueUrl: text("issue_url").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  uniqueIndex("idx_github_issues_user_repo_finding").on(table.userId, table.repoFullName, table.findingKey),
  index("idx_github_issues_report").on(table.reportId),
]);

export type GithubIssue = typeof githubIssuesTable.$inferSelect;

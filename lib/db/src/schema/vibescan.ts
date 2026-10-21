import { pgTable, text, uuid, integer, timestamp, jsonb, index, uniqueIndex, varchar, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
export { monitorSubscriptionsTable, cveAlertsTable, monitorScoreHistoryTable, monitorRegressionsTable, certExpiryAlertsTable, monitorPulseChecksTable, insertMonitorSubscriptionSchema, insertCveAlertSchema } from "./vibescanMonitor";
export { creditsTable, purchaseIntentsTable, billingSubscriptionsTable, stripeEventsTable, apiTokensTable, insertCreditSchema } from "./vibescanBilling";
export type { MonitorScoreHistory, InsertMonitorScoreHistory, MonitorRegression, InsertMonitorRegression, CertExpiryAlert, InsertCertExpiryAlert, MonitorPulseCheck, InsertMonitorPulseCheck, InsertMonitorSubscription, MonitorSubscription, InsertCveAlert, CveAlert } from "./vibescanMonitor";
export type { PurchaseIntent, InsertCredit, Credit } from "./vibescanBilling";

export const scansTable = pgTable("scans", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email").notNull(),
  targetUrl: text("target_url").notNull(),
  // The tests finished so far, written while the scan runs so the progress page
  // shows what actually happened. See lib/liveProgress.ts. Null until the first one.
  liveTests: jsonb("live_tests").$type<unknown[] | null>(),
  tier: text("tier", { enum: ["basic", "deep", "pack_5", "pack_20"] }).notNull(),
  status: text("status", {
    enum: ["pending", "paid", "queued", "scanning", "analyzing", "complete", "failed"],
  }).notNull().default("pending"),
  stripeSessionId: text("stripe_session_id"),
  stripePaymentIntentId: text("stripe_payment_intent_id"),

  // Who asked for this scan. "monitor" rows are created by the monitor
  // scheduler and by subscription setup — nobody pressed a button for them —
  // so they must not be counted against a user's free-scan allowance. Deliberately
  // not a foreign key to the subscription: a scan is a historical record that
  // outlives the subscription, and cascading a delete into NULL here would
  // silently reclassify an old monitor scan as user-initiated and start
  // charging it against the trial.
  origin: text("origin", { enum: ["user", "monitor", "verify"] }).notNull().default("user"),

  // What paid for this scan, recorded at launch so a scan that fails later can
  // be refunded to the SAME place. Without it a failure could not tell a free
  // trial scan (nothing to give back) from a bought credit (must give back)
  // from a subscription's included scan (give back to this month's allowance).
  // Null for rows created before this column, and for monitor scans, which
  // nothing pays for.
  paidWith: text("paid_with", { enum: ["free", "included", "credit"] }),

  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  startedAt: timestamp("started_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  error: text("error"),

  // Credentials for an authenticated scan, AES-256-GCM encrypted with
  // ENCRYPTION_KEY (see api-server/src/lib/crypto.ts). Deliberately stored here
  // rather than in the pg-boss job payload, which is plaintext in the queue
  // table. Cleared when the scan finishes, so the window in which they exist at
  // all is one scan long.
  credentialsEncrypted: text("credentials_encrypted"),
  // A second account, for broken access control testing. Same handling as the
  // primary: encrypted, and cleared when the scan ends.
  secondaryCredentialsEncrypted: text("secondary_credentials_encrypted"),
  // Recorded when the requester attested they may test this target with these
  // credentials — automated sign-in is a different legal posture from an
  // unauthenticated header check, and the claim should outlive the credentials.
  credentialsAuthorizedAt: timestamp("credentials_authorized_at", { withTimezone: true }),
  // A public GitHub repository the requester asked us to read for secrets, stored as the
  // normalised https://github.com/owner/repo URL. Not a secret (the repository is public),
  // so unlike the credentials it stays after the scan and the report can say what was read.
  githubRepoUrl: text("github_repo_url"),
  // The GitHub App installation this scan may read the repository through, when the repository is private
  // and its owner has shared it with SecScan. Set only after the requester was checked against the
  // installation (githubInstallationAccess.ts); never taken from the request. An installation id is not a
  // secret: the access token it yields is minted by the worker for one scan and is never stored.
  githubInstallationId: text("github_installation_id"),
  // The requester's explicit opt-in to let the scan create a disposable second account through the
  // target's public signup form (autoSecondAccount.ts). Off unless asked for, and only meaningful
  // when credentials were supplied, since the test compares them with the new account.
  autoSecondAccount: boolean("auto_second_account").notNull().default(false),
}, (table) => [
  index("idx_scans_user_id").on(table.userId),
  // The daily quota count (routes/scansCreate.ts) filters on user and a
  // created_at range; this serves it without reading every scan the user has.
  index("idx_scans_user_created").on(table.userId, table.createdAt),
  index("idx_scans_status").on(table.status),
]);

// ── Out-of-band interaction collector ────────────────────────────────────────
// Powers SSRF and blind-vulnerability detection. A probe injects a URL back to
// this app carrying a unique token; if the target's server fetches it, the hit
// lands here and proves the vulnerability. Only registered, unexpired tokens
// are recorded, so an internet-facing callback route cannot be turned into an
// unbounded write by anyone spraying random paths.
export const oobTokensTable = pgTable(
  "oob_tokens",
  {
    token: varchar("token").primaryKey(),
    scanId: uuid("scan_id").references(() => scansTable.id, { onDelete: "cascade" }),
    // What the token was planted in, for the finding's evidence.
    context: text("context"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (table) => [index("idx_oob_tokens_scan").on(table.scanId)],
);

export const oobInteractionsTable = pgTable(
  "oob_interactions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    token: varchar("token").notNull(),
    method: varchar("method"),
    path: text("path"),
    // The address that made the callback — often the target's own egress IP,
    // which is itself evidence of a server-side request.
    sourceIp: varchar("source_ip"),
    userAgent: text("user_agent"),
    receivedAt: timestamp("received_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("idx_oob_interactions_token").on(table.token)],
);

export type OobInteraction = typeof oobInteractionsTable.$inferSelect;

export const reportsTable = pgTable("reports", {
  id: uuid("id").primaryKey().defaultRandom(),
  scanId: uuid("scan_id").references(() => scansTable.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull(),
  targetUrl: text("target_url").notNull(),
  tier: text("tier", { enum: ["basic", "deep", "pack_5", "pack_20"] }).notNull(),
  scannedAt: timestamp("scanned_at", { withTimezone: true }).notNull().defaultNow(),
  duration: integer("duration"),
  data: jsonb("data").notNull(),
  pdfUrl: text("pdf_url"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_reports_user_id").on(table.userId),
  index("idx_reports_scan_id").on(table.scanId),
]);

/**
 * What someone thought after actually using the product.
 *
 * The free-scan cap exists to get this: people scanning apps they own and
 * telling us what worked. `rating` is a coarse 1-5 self-report, not a metric
 * anything downstream computes on — it is here so a page of feedback can be
 * skimmed by how positive it was without opening each row. `context` records
 * where in the app the form was opened from (a report, the dashboard, the
 * cap) because "this is confusing" means something different on each.
 *
 * userId is nullable on purpose: an anonymous scan is still a real user with a
 * real opinion, and account creation must never be the price of being heard.
 */
export const feedbackTable = pgTable("feedback", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id"),
  email: text("email"),
  message: text("message").notNull(),
  rating: integer("rating"),
  context: text("context"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type Feedback = typeof feedbackTable.$inferSelect;

/**
 * Proof that a user controls a domain, which is what unlocks active offensive
 * probing against it. Without this the scanner would fire attack payloads at
 * any host someone types in, which is both a legal problem for us and an
 * anonymous attack proxy for everyone else.
 *
 * One row per (user, domain). `verifiedAt` null means the challenge has been
 * issued but not yet satisfied; the token stays so the user can retry.
 */
export const domainVerificationsTable = pgTable("domain_verifications", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  domain: text("domain").notNull(),
  token: text("token").notNull(),
  method: text("method", { enum: ["dns", "well_known"] }),
  verifiedAt: timestamp("verified_at", { withTimezone: true }),
  lastCheckedAt: timestamp("last_checked_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  uniqueIndex("idx_domain_verif_user_domain").on(table.userId, table.domain),
  index("idx_domain_verif_user").on(table.userId),
]);

export const insertScanSchema = createInsertSchema(scansTable).omit({
  id: true,
  createdAt: true,
  startedAt: true,
  completedAt: true,
});
export type InsertScan = typeof scansTable.$inferInsert;
export type Scan = typeof scansTable.$inferSelect;

export const insertReportSchema = createInsertSchema(reportsTable).omit({
  id: true,
  scannedAt: true,
  createdAt: true,
});
export type InsertReport = typeof reportsTable.$inferInsert;
export type Report = typeof reportsTable.$inferSelect;

/**
 * GitHub App installations an account has proven it can use, for scanning private repositories.
 *
 * A row is written only by the Connect GitHub callback, after GitHub itself listed the installation for the signed-in
 * person's own GitHub authorisation (GET /user/installations). An installation id is not a secret, so it is never
 * taken from a request: this table is what a scan checks before it reads a private repository. The GitHub user token
 * used to prove it is discarded straight after; nothing here is a credential.
 */
export const githubInstallationsTable = pgTable("github_installations", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  installationId: text("installation_id").notNull(),
  /** The GitHub account or organisation the app is installed on, for showing to the person. */
  accountLogin: text("account_login"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  uniqueIndex("idx_github_installations_user_installation").on(table.userId, table.installationId),
  index("idx_github_installations_user").on(table.userId),
]);

/**
 * Free scans used this month by an account that has since been deleted, so deleting and re-registering
 * does not hand out a fresh allowance. Holds a keyed hash of the address, never the address, and only
 * for the month it applies to: rows from earlier months are deleted as they are met.
 */
export const deletedAccountTrialsTable = pgTable("deleted_account_trials", {
  emailHash: text("email_hash").primaryKey(),
  periodStart: timestamp("period_start", { withTimezone: true }).notNull(),
  scansUsed: integer("scans_used").notNull(),
});

export const dismissedFindingsTable = pgTable("dismissed_findings", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  targetUrl: text("target_url").notNull(),
  findingFingerprint: text("finding_fingerprint").notNull(),
  findingName: text("finding_name").notNull(),
  findingCategory: text("finding_category").notNull(),
  reason: text("reason").default("false_positive"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_dismissed_user_target").on(table.userId, table.targetUrl),
  uniqueIndex("uq_dismissed_user_target_fp").on(table.userId, table.targetUrl, table.findingFingerprint),
]);

export type DismissedFinding = typeof dismissedFindingsTable.$inferSelect;

export const reportSharesTable = pgTable("report_shares", {
  id: uuid("id").primaryKey().defaultRandom(),
  reportId: uuid("report_id").notNull().references(() => reportsTable.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull(),
  // SHA-256 (hex) of the token in the link. The token itself is shown once, at creation, and never stored:
  // a leaked database or backup then holds no working share links.
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (table) => [
  uniqueIndex("uq_report_shares_token_hash").on(table.tokenHash),
  index("idx_report_shares_report_id").on(table.reportId),
  index("idx_report_shares_user_id").on(table.userId),
]);

export type ReportShare = typeof reportSharesTable.$inferSelect;

/**
 * A public grade badge for one report.
 *
 * Deliberately NOT a share token. A share token is a bearer credential for the whole
 * report, findings included, so putting one in a README would hand every reader the
 * report. A badge token opens exactly one thing, a small image showing the grade and
 * the scan date, and nothing else; it can be revoked on its own without touching the
 * report's share links. The grade is read from the report when the image is requested,
 * so the table stores no copy of it.
 */
export const reportBadgesTable = pgTable("report_badges", {
  id: uuid("id").primaryKey().defaultRandom(),
  reportId: uuid("report_id").notNull().references(() => reportsTable.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull(),
  token: text("token").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (table) => [
  uniqueIndex("uq_report_badges_token").on(table.token),
  index("idx_report_badges_report_id").on(table.reportId),
]);

export type ReportBadge = typeof reportBadgesTable.$inferSelect;

export const eolCacheTable = pgTable("eol_cache", {
  key: text("key").primaryKey(),
  payload: jsonb("payload").notNull(),
  fetchedAt: timestamp("fetched_at", { withTimezone: true }).notNull(),
});
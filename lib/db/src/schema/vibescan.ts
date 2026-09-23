import { pgTable, text, uuid, integer, timestamp, jsonb, real, index, uniqueIndex, varchar, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const scansTable = pgTable("scans", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email").notNull(),
  targetUrl: text("target_url").notNull(),
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
  origin: text("origin", { enum: ["user", "monitor"] }).notNull().default("user"),

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
}, (table) => [
  index("idx_scans_user_id").on(table.userId),
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

export const monitorSubscriptionsTable = pgTable("monitor_subscriptions", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").notNull(),
  userEmail: text("user_email").notNull(),
  targetUrl: text("target_url").notNull(),
  status: text("status", { enum: ["active", "cancelled", "expired"] }).notNull().default("active"),
  subscribedAt: timestamp("subscribed_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  lastScanAt: timestamp("last_scan_at", { withTimezone: true }),
  lastReportId: uuid("last_report_id"),
  nextScanAt: timestamp("next_scan_at", { withTimezone: true }),
  webhookUrl: text("webhook_url"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_monitor_user_id").on(table.userId),
  index("idx_monitor_status").on(table.status),
  index("idx_monitor_target").on(table.targetUrl),
  index("idx_monitor_next_scan").on(table.nextScanAt),
]);

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
  // "pro" is the one plan sold today ($50/month: 3 monitored sites + 5 scans a
  // month). solo/studio/agency were designed but never sold; kept in the enum so
  // no historical row can fail to parse.
  plan: text("plan", { enum: ["pro", "solo", "studio", "agency", "grandfathered"] }).notNull(),
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
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (table) => [
  index("idx_api_tokens_user").on(table.userId),
]);

export const cveAlertsTable = pgTable("cve_alerts", {
  id: uuid("id").primaryKey().defaultRandom(),
  subscriptionId: uuid("subscription_id").notNull().references(() => monitorSubscriptionsTable.id, { onDelete: "cascade" }),
  cveId: text("cve_id").notNull(),
  cveSummary: text("cve_summary").notNull(),
  affectedTech: text("affected_tech").notNull(),
  severity: text("severity").notNull(),
  epssScore: real("epss_score"),
  epssPercentile: real("epss_percentile"),
  triggerScanId: uuid("trigger_scan_id"),
  detectedAt: timestamp("detected_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_cve_alerts_subscription_id").on(table.subscriptionId),
  index("idx_cve_alerts_cve_id").on(table.cveId),
]);

// ── Monitor score history ──────────────────────────────────────────────────────

export const monitorScoreHistoryTable = pgTable("monitor_score_history", {
  id: uuid("id").primaryKey().defaultRandom(),
  subscriptionId: uuid("subscription_id").notNull().references(() => monitorSubscriptionsTable.id, { onDelete: "cascade" }),
  scanId: uuid("scan_id").references(() => scansTable.id, { onDelete: "set null" }),
  grade: text("grade").notNull(),
  riskScore: integer("risk_score").notNull(),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  scannedAt: timestamp("scanned_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_score_history_sub_id").on(table.subscriptionId),
  index("idx_score_history_scanned_at").on(table.scannedAt),
]);

export type MonitorScoreHistory = typeof monitorScoreHistoryTable.$inferSelect;
export type InsertMonitorScoreHistory = typeof monitorScoreHistoryTable.$inferInsert;

// ── Monitor regressions ────────────────────────────────────────────────────────

export const monitorRegressionsTable = pgTable("monitor_regressions", {
  id: uuid("id").primaryKey().defaultRandom(),
  subscriptionId: uuid("subscription_id").notNull().references(() => monitorSubscriptionsTable.id, { onDelete: "cascade" }),
  scanId: uuid("scan_id").references(() => scansTable.id, { onDelete: "set null" }),
  checkId: text("check_id").notNull(),
  checkTitle: text("check_title").notNull(),
  severity: text("severity").notNull(),
  detectedAt: timestamp("detected_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_regressions_sub_id").on(table.subscriptionId),
  index("idx_regressions_scan_id").on(table.scanId),
  uniqueIndex("uq_regression_sub_scan_check").on(table.subscriptionId, table.scanId, table.checkId),
]);

export type MonitorRegression = typeof monitorRegressionsTable.$inferSelect;
export type InsertMonitorRegression = typeof monitorRegressionsTable.$inferInsert;

// ── Certificate expiry alerts ──────────────────────────────────────────────────

export const certExpiryAlertsTable = pgTable("cert_expiry_alerts", {
  id: uuid("id").primaryKey().defaultRandom(),
  subscriptionId: uuid("subscription_id").notNull().references(() => monitorSubscriptionsTable.id, { onDelete: "cascade" }),
  expiryDate: timestamp("expiry_date", { withTimezone: true }).notNull(),
  daysRemaining: integer("days_remaining").notNull(),
  alertThreshold: integer("alert_threshold").notNull(),
  sentAt: timestamp("sent_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_cert_expiry_sub_id").on(table.subscriptionId),
  uniqueIndex("uq_cert_expiry_sub_threshold").on(table.subscriptionId, table.alertThreshold, table.expiryDate),
]);

export type CertExpiryAlert = typeof certExpiryAlertsTable.$inferSelect;
export type InsertCertExpiryAlert = typeof certExpiryAlertsTable.$inferInsert;

// ── Hourly pulse checks ────────────────────────────────────────────────────────

/**
 * One cheap check per monitored URL per hour.
 *
 * A full rescan is minutes of work, several paid API calls and real traffic at
 * the customer's site, which is why the cadence is measured in days. That left
 * a monitoring product with nothing to show between rescans: a site could go
 * down, lose its HSTS header or start redirecting somewhere new, and the
 * dashboard would keep displaying a grade from eleven days ago with no
 * indication anyone had looked since.
 *
 * A pulse is one request plus one TLS handshake. It cannot grade a site, and it
 * is not meant to — it answers "is it up, is the certificate still good, and
 * has anything visible changed since the last hour", and it gives the dashboard
 * a last-checked time that is never more than an hour old.
 *
 * Rows are purged after PULSE_RETENTION_DAYS. They are a rolling window for
 * uptime and response-time trends, not a permanent record; the permanent record
 * is monitor_score_history.
 */
export const monitorPulseChecksTable = pgTable("monitor_pulse_checks", {
  id: uuid("id").primaryKey().defaultRandom(),
  subscriptionId: uuid("subscription_id").notNull().references(() => monitorSubscriptionsTable.id, { onDelete: "cascade" }),
  checkedAt: timestamp("checked_at", { withTimezone: true }).notNull().defaultNow(),
  /** Answered with a status below 500. A 404 is reachable; a 503 is not. */
  reachable: boolean("reachable").notNull(),
  httpStatus: integer("http_status"),
  responseTimeMs: integer("response_time_ms"),
  /** Where the request ended up. A changed redirect target is its own signal. */
  finalUrl: text("final_url"),
  /** Hash over the security headers listed in monitorPulse.ts, for change detection. */
  headerFingerprint: text("header_fingerprint"),
  /** Which of those headers were present, so a diff can name what went missing. */
  presentHeaders: jsonb("present_headers").$type<string[]>(),
  /**
   * HSTS strength, bucketed. Stored separately from presentHeaders because a
   * Strict-Transport-Security header with max-age=0 is still present while
   * doing nothing — presence alone cannot see that being switched off.
   */
  hstsBucket: text("hsts_bucket", { enum: ["none", "short", "ok"] }),
  certExpiresAt: timestamp("cert_expires_at", { withTimezone: true }),
  certDaysRemaining: integer("cert_days_remaining"),
  /** Why the request failed, when it did. Null on success. */
  failureReason: text("failure_reason"),
}, (table) => [
  // Every read is "the newest N for one subscription", so the index carries the
  // sort as well as the filter.
  index("idx_pulse_sub_checked").on(table.subscriptionId, table.checkedAt),
  index("idx_pulse_checked_at").on(table.checkedAt),
]);

export type MonitorPulseCheck = typeof monitorPulseChecksTable.$inferSelect;
export type InsertMonitorPulseCheck = typeof monitorPulseChecksTable.$inferInsert;

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

export const insertCreditSchema = createInsertSchema(creditsTable).omit({
  id: true,
  updatedAt: true,
});
export type InsertCredit = typeof creditsTable.$inferInsert;
export type Credit = typeof creditsTable.$inferSelect;

export const insertMonitorSubscriptionSchema = createInsertSchema(monitorSubscriptionsTable).omit({
  id: true,
  subscribedAt: true,
  createdAt: true,
});
export type InsertMonitorSubscription = typeof monitorSubscriptionsTable.$inferInsert;
export type MonitorSubscription = typeof monitorSubscriptionsTable.$inferSelect;

export const insertCveAlertSchema = createInsertSchema(cveAlertsTable).omit({
  id: true,
  detectedAt: true,
});
export type InsertCveAlert = typeof cveAlertsTable.$inferInsert;
export type CveAlert = typeof cveAlertsTable.$inferSelect;

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
  token: text("token").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (table) => [
  uniqueIndex("uq_report_shares_token").on(table.token),
  index("idx_report_shares_report_id").on(table.reportId),
  index("idx_report_shares_user_id").on(table.userId),
]);

export type ReportShare = typeof reportSharesTable.$inferSelect;

export const eolCacheTable = pgTable("eol_cache", {
  key: text("key").primaryKey(),
  payload: jsonb("payload").notNull(),
  fetchedAt: timestamp("fetched_at", { withTimezone: true }).notNull(),
});

/** Monitoring tables: subscriptions, alerts, score history, regressions, certificate expiry and pulse checks. */
import { pgTable, text, uuid, integer, timestamp, jsonb, real, index, uniqueIndex, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { scansTable } from "./vibescan";

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
  // Set while the owner has paused this monitor: no scans, pulse checks or alerts, and nothing
  // is lost. Null means running. Kept separate from status so a pause is never confused with a
  // cancellation or an unpaid plan, and resuming needs no re-subscription.
  pausedAt: timestamp("paused_at", { withTimezone: true }),
  // Days between full rescans, when the owner chose one (3, 7, 14 or 30). Null means the
  // default: the grade sets the cadence. Never more often than the grade cadence's 3-day floor.
  scanIntervalDays: integer("scan_interval_days"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => [
  index("idx_monitor_user_id").on(table.userId),
  index("idx_monitor_status").on(table.status),
  index("idx_monitor_target").on(table.targetUrl),
  index("idx_monitor_next_scan").on(table.nextScanAt),
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

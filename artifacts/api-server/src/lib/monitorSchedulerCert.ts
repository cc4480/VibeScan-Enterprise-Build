/** Certificate expiry alerts. */
import { db, reportsTable, certExpiryAlertsTable, monitorPulseChecksTable } from "@workspace/db";
import { eq, and, desc } from "drizzle-orm";
import { sameSite } from "./urlKey";
import { logger } from "./logger";
import { sendCertExpiryEmail } from "./mailer";
import { fireWebhook } from "./webhook";
import { APP_ORIGIN } from "./appOrigin";
import { activeEntitledSubscriptions, type ActiveSub } from "./monitorSchedulerSweep";
import { certAlertThresholds } from "./monitorPulseCert";

export const CERT_QUEUE       = "monitor-cert-expiry";

// ─── 4. Certificate expiry ────────────────────────────────────────────────────

/** The widest set. A short-lived, auto-renewing certificate skips 30; see certAlertThresholds. */
export const CERT_THRESHOLDS = [30, 14, 7] as const;

/** A pulse reading newer than this has already been through maybeAlertCertExpiry. */
const RECENT_PULSE_MS = 3 * 3_600_000;

/**
 * Alert on a certificate that is about to expire, at most once per threshold
 * per certificate cycle.
 *
 * Shared by the hourly pulse check, which passes the certificate it just read
 * off a live handshake, and by the daily job, which passes whatever was last
 * recorded. Extracted so those two cannot drift: the dedupe rule is the only
 * thing standing between "one warning at 30, 14 and 7 days" and "a warning
 * every hour for a month".
 */
export async function maybeAlertCertExpiry(
  sub: Pick<ActiveSub, "id" | "userId" | "userEmail" | "targetUrl" | "webhookUrl">,
  expiryDate: Date,
  now: Date,
  appOrigin: string,
  log: typeof logger,
  issuedAt: Date | null = null,
): Promise<void> {
  if (Number.isNaN(expiryDate.getTime())) return;

  const thresholds = certAlertThresholds(issuedAt, expiryDate);
  const daysRemaining = Math.ceil((expiryDate.getTime() - now.getTime()) / 86_400_000);
  if (daysRemaining <= 0 || daysRemaining > thresholds[0]!) return;

  for (const threshold of thresholds) {
    if (daysRemaining > threshold) continue;

    // Already alerted at this threshold for this certificate cycle? The expiry
    // date is part of the key so a renewal — which is a new cycle with a new
    // date — starts the thresholds again.
    const existing = await db
      .select({ id: certExpiryAlertsTable.id })
      .from(certExpiryAlertsTable)
      .where(
        and(
          eq(certExpiryAlertsTable.subscriptionId, sub.id),
          eq(certExpiryAlertsTable.alertThreshold, threshold),
          eq(certExpiryAlertsTable.expiryDate, expiryDate),
        ),
      )
      .limit(1);

    if (existing.length > 0) continue;

    await db.insert(certExpiryAlertsTable).values({
      subscriptionId: sub.id,
      expiryDate,
      daysRemaining,
      alertThreshold: threshold,
    });

    log.info(
      { subscriptionId: sub.id, targetUrl: sub.targetUrl, daysRemaining, threshold },
      "Cert expiry alert fired",
    );

    if (sub.userEmail) {
      await sendCertExpiryEmail({
        toEmail: sub.userEmail,
        userId: sub.userId,
        targetUrl: sub.targetUrl,
        daysRemaining,
        expiryDate,
        dashboardUrl: `${appOrigin}/monitor`,
      });
    }

    if (sub.webhookUrl) {
      await fireWebhook(sub.webhookUrl, "cert_expiry", sub.targetUrl, sub.id, {
        daysRemaining,
        expiryDate: expiryDate.toISOString(),
        alertThreshold: threshold,
      // No severity: days-remaining is not one, and passing a made-up
      // value here would let a raised floor hide expiry warnings.
      }, { userId: sub.userId });
    }

    // One threshold per run, so a subscription added late — or one that
    // missed runs while the worker was down — sends a reminder a day
    // rather than three at once. CERT_THRESHOLDS is ordered [30, 14, 7],
    // so this fires the WIDEST unalerted band first, not the narrowest;
    // the email still quotes the real daysRemaining, so its content is
    // correct either way and only the recorded threshold differs.
    return;
  }
}

/**
 * The daily safety net behind the pulse check.
 *
 * The pulse reads the certificate live every hour, so in normal operation this
 * finds nothing left to do. It stays because it is the path that still works
 * when the pulse cannot complete a handshake at all, and because the
 * certificate reading it falls back to — the last scan report — is the only
 * source for a site the pulse has never reached.
 */
export async function runCertExpiryCheck(): Promise<void> {
  const log = logger.child({ job: CERT_QUEUE });
  const now = new Date();

  const { subs, total, skippedUnentitled } = await activeEntitledSubscriptions(now);
  log.info(
    { total, subscriptions: subs.length, skippedUnentitled },
    "Running daily certificate expiry check",
  );

  const appOrigin = APP_ORIGIN;

  for (const sub of subs) {
    try {
      let expiryDate: Date | null = null;
      let issuedAt: Date | null = null;

      // Newest live reading first.
      const [livePulse] = await db
        .select({ certExpiresAt: monitorPulseChecksTable.certExpiresAt, checkedAt: monitorPulseChecksTable.checkedAt })
        .from(monitorPulseChecksTable)
        .where(
          and(
            eq(monitorPulseChecksTable.subscriptionId, sub.id),
            eq(monitorPulseChecksTable.reachable, true),
          ),
        )
        .orderBy(desc(monitorPulseChecksTable.checkedAt))
        .limit(1);

      if (livePulse?.certExpiresAt && now.getTime() - livePulse.checkedAt.getTime() < RECENT_PULSE_MS) {
        // The pulse evaluated this certificate within the last few hours, with its issue date,
        // which is not stored. Alerting again here without that date would bring back the 30-day
        // warning the pulse deliberately skips for an auto-renewing certificate.
        continue;
      } else if (livePulse?.certExpiresAt) {
        // The pulse has not reached the site for a while; warn from the last reading it took.
        expiryDate = livePulse.certExpiresAt;
      } else {
        // Fall back to the scan report. This value can be as old as the scan
        // cadence — up to fourteen days on an A-grade site — which is exactly
        // why the pulse reading is preferred.
        const [latestReport] = await db
          .select({ data: reportsTable.data })
          .from(reportsTable)
          .where(
            and(
              eq(reportsTable.userId, sub.userId),
              sameSite(reportsTable.targetUrl, sub.targetUrl),
            ),
          )
          .orderBy(desc(reportsTable.createdAt))
          .limit(1);

        if (!latestReport) continue;

        const reportData = latestReport.data as {
          tlsGrade?: string;
          certExpiry?: string | null;
          certIssuedAt?: string | null;
          rawData?: { certExpiry?: string | null };
        };

        const certExpiryRaw = reportData.certExpiry ?? reportData.rawData?.certExpiry ?? null;
        if (!certExpiryRaw) continue;
        expiryDate = new Date(certExpiryRaw);
        issuedAt = reportData.certIssuedAt ? new Date(reportData.certIssuedAt) : null;
      }

      if (!expiryDate) continue;
      await maybeAlertCertExpiry(sub, expiryDate, now, appOrigin, log, issuedAt);
    } catch (err) {
      log.error({ err, subscriptionId: sub.id }, "Cert expiry check failed for subscription");
    }
  }
}

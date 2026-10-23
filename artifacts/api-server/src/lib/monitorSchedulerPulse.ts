/** The availability/header pulse check. */
import { db, monitorPulseChecksTable } from "@workspace/db";
import { eq, and, lt, desc } from "drizzle-orm";
import { logger } from "./logger";
import { sendAvailabilityEmail, sendDriftEmail } from "./mailer";
import { fireWebhook } from "./webhook";
import { APP_ORIGIN } from "./appOrigin";
import { highestSeverity } from "./notificationPrefs";
import { runPulse, evaluateAvailability, evaluateDrift, certDaysRemaining, PULSE_RETENTION_DAYS, DOWN_THRESHOLD, type HstsBucket } from "./monitorPulse";
import { activeEntitledSubscriptions, type ActiveSub } from "./monitorSchedulerSweep";
import { maybeAlertCertExpiry } from "./monitorSchedulerCert";

export const PULSE_QUEUE      = "monitor-pulse";

// ─── 2. Hourly pulse job ──────────────────────────────────────────────────────

/**
 * How many sites are probed at once.
 *
 * Kept low on purpose. These requests go to other people's production servers,
 * and a monitoring product that arrives as a burst of simultaneous traffic every
 * hour is a nuisance at best and looks like an attack at worst.
 */
export const PULSE_CONCURRENCY = 5;

/** What one pulse did, so the run can summarise instead of logging nothing. */
export interface PulseOutcome {
  reachable: boolean;
  availabilityAlert: boolean;
  driftFindings: number;
}

export async function pulseOne(sub: ActiveSub, appOrigin: string): Promise<PulseOutcome> {
  const log = logger.child({ job: PULSE_QUEUE, subscriptionId: sub.id });
  const outcome: PulseOutcome = { reachable: false, availabilityAlert: false, driftFindings: 0 };

  const result = await runPulse(sub.targetUrl);

  // The recent run, newest first, for the availability state machine.
  const earlier = await db
    .select({
      reachable: monitorPulseChecksTable.reachable,
      checkedAt: monitorPulseChecksTable.checkedAt,
    })
    .from(monitorPulseChecksTable)
    .where(eq(monitorPulseChecksTable.subscriptionId, sub.id))
    .orderBy(desc(monitorPulseChecksTable.checkedAt))
    .limit(DOWN_THRESHOLD + 3);

  // The last pulse that actually reached the site, for the header comparison.
  // A separate query rather than a scan of the rows above, because a site that
  // has been down for longer than that window still needs something to diff
  // against once it returns.
  const [lastSuccess] = await db
    .select({
      headerFingerprint: monitorPulseChecksTable.headerFingerprint,
      presentHeaders: monitorPulseChecksTable.presentHeaders,
      finalUrl: monitorPulseChecksTable.finalUrl,
      hstsBucket: monitorPulseChecksTable.hstsBucket,
      checkedAt: monitorPulseChecksTable.checkedAt,
    })
    .from(monitorPulseChecksTable)
    .where(
      and(
        eq(monitorPulseChecksTable.subscriptionId, sub.id),
        eq(monitorPulseChecksTable.reachable, true),
      ),
    )
    .orderBy(desc(monitorPulseChecksTable.checkedAt))
    .limit(1);

  // The moment THIS check finished, not the moment the run started. With a
  // batch of forty sites at a concurrency of five, a shared timestamp would
  // have every row in the run claiming the same instant, and the dashboard's
  // "checked 3 minutes ago" would be wrong by however long the batch took.
  const checkedAt = new Date();
  const certDays = certDaysRemaining(result.certExpiresAt, checkedAt);

  await db.insert(monitorPulseChecksTable).values({
    subscriptionId: sub.id,
    checkedAt,
    reachable: result.reachable,
    httpStatus: result.httpStatus,
    responseTimeMs: result.responseTimeMs,
    finalUrl: result.finalUrl,
    headerFingerprint: result.snapshot?.fingerprint ?? null,
    presentHeaders: result.snapshot?.present ?? null,
    hstsBucket: result.snapshot?.hsts ?? null,
    certExpiresAt: result.certExpiresAt,
    certDaysRemaining: certDays,
    failureReason: result.failureReason,
  });

  outcome.reachable = result.reachable;

  // ── Availability ──
  const availability = evaluateAvailability(earlier, result);
  if (availability) {
    outcome.availabilityAlert = true;
    const consecutiveFailures = availability === "down" ? DOWN_THRESHOLD : 0;
    log.warn({ event: availability, status: result.httpStatus }, "Availability change detected");

    if (sub.userEmail) {
      await sendAvailabilityEmail({
        toEmail: sub.userEmail,
        userId: sub.userId,
        targetUrl: sub.targetUrl,
        event: availability,
        failureReason: result.failureReason,
        consecutiveFailures,
        lastSeenUpAt: lastSuccess?.checkedAt ?? null,
        dashboardUrl: `${appOrigin}/monitor`,
      });
    }

    if (sub.webhookUrl) {
      await fireWebhook(
        sub.webhookUrl,
        availability === "down" ? "site_down" : "site_recovered",
        sub.targetUrl,
        sub.id,
        {
          failureReason: result.failureReason,
          consecutiveFailures,
          httpStatus: result.httpStatus,
        },
        // No severity: "unreachable" is not one, and inventing a value here
        // would let a raised floor hide an outage.
        { userId: sub.userId },
      );
    }
  }

  // ── Configuration drift ──
  if (result.snapshot) {
    const changes = evaluateDrift(
      lastSuccess ?? null,
      { snapshot: result.snapshot, finalUrl: result.finalUrl },
      (lastSuccess?.hstsBucket as HstsBucket | null) ?? undefined,
    );

    if (changes.length > 0) {
      outcome.driftFindings = changes.length;
      const severity = highestSeverity(changes);
      log.warn({ changes: changes.map((c) => c.kind), severity }, "Security drift detected");

      if (sub.userEmail) {
        await sendDriftEmail({
          toEmail: sub.userEmail,
          userId: sub.userId,
          targetUrl: sub.targetUrl,
          changes,
          severity,
          dashboardUrl: `${appOrigin}/monitor`,
        });
      }

      if (sub.webhookUrl) {
        await fireWebhook(
          sub.webhookUrl,
          "security_drift",
          sub.targetUrl,
          sub.id,
          { changes },
          { userId: sub.userId, severity },
        );
      }
    }
  }

  // ── Certificate expiry, from the live handshake ──
  //
  // The daily job reads a stored value that can be a fortnight old. This is the
  // certificate as it is right now, which is the difference between warning
  // somebody at seven days and warning them after it already expired.
  if (result.certExpiresAt) {
    await maybeAlertCertExpiry(sub, result.certExpiresAt, checkedAt, appOrigin, log, result.certIssuedAt);
  }

  return outcome;
}

export async function runPulseCheck(): Promise<void> {
  const log = logger.child({ job: PULSE_QUEUE });
  const now = new Date();

  const { subs, total, skippedUnentitled } = await activeEntitledSubscriptions(now);
  log.info({ total, checking: subs.length, skippedUnentitled }, "Running hourly pulse check");

  const appOrigin = APP_ORIGIN;

  let up = 0;
  let down = 0;
  let errored = 0;
  let availabilityAlerts = 0;
  let driftFindings = 0;

  for (let i = 0; i < subs.length; i += PULSE_CONCURRENCY) {
    const batch = subs.slice(i, i + PULSE_CONCURRENCY);
    const outcomes = await Promise.all(
      batch.map((sub) =>
        // One site failing must not abandon the rest of the batch, so each is
        // caught here rather than letting Promise.all reject.
        pulseOne(sub, appOrigin).catch((err) => {
          log.error({ err, subscriptionId: sub.id }, "Pulse check failed for subscription");
          return null;
        }),
      ),
    );

    for (const outcome of outcomes) {
      if (!outcome) { errored++; continue; }
      if (outcome.reachable) up++;
      else down++;
      if (outcome.availabilityAlert) availabilityAlerts++;
      driftFindings += outcome.driftFindings;
    }
  }

  // Logged on every run, including the quiet ones.
  //
  // Before this, a pulse run that worked logged its start line and nothing
  // else: the purge is silent when it finds nothing, and no site being down is
  // the normal case. So a successful run and a run whose every insert failed
  // looked identical in the logs — the same defect as the monitor update in
  // worker.ts that claimed success whether or not it matched a row.
  log.info(
    { checked: subs.length, up, down, errored, availabilityAlerts, driftFindings },
    "Hourly pulse check complete",
  );

  // Rolling window: pulse rows exist for uptime and response-time trends, not
  // as a permanent record. Without this, one subscription accumulates 8,760
  // rows a year for data nobody looks at past the first month.
  const cutoff = new Date(now.getTime() - PULSE_RETENTION_DAYS * 86_400_000);
  const purged = await db
    .delete(monitorPulseChecksTable)
    .where(lt(monitorPulseChecksTable.checkedAt, cutoff))
    .returning({ id: monitorPulseChecksTable.id });

  if (purged.length > 0) {
    log.info({ purged: purged.length, olderThanDays: PULSE_RETENTION_DAYS }, "Purged old pulse rows");
  }
}

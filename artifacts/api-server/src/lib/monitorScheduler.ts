/**
 * Monitor Scheduler — 2026 continuous monitoring standard.
 *
 * Jobs:
 *  1. monitor-sweep  (every 6 h) — risk-adaptive rescan sweep
 *     Replaces the fixed Sunday-only weekly scan. After each scan completes,
 *     nextScanAt is set based on the resulting grade (A→14d, B/C→7d, D/F→3d).
 *     This sweep finds all subscriptions where nextScanAt ≤ now and enqueues them.
 *
 *  2. monitor-pulse  (hourly)
 *     One request and one TLS handshake per monitored URL. Records reachability,
 *     response time, security-header presence and live certificate expiry, then
 *     alerts on an outage, on a recovery, and on any change that weakens the
 *     site. See lib/monitorPulse.ts for why this exists and what it deliberately
 *     does not do.
 *
 *  3. monitor-cve-check  (hourly)
 *     Fetches CVEs from NVD, matches them against each active subscription's tech
 *     stack, enriches matches with EPSS scores from api.first.org, creates
 *     cve_alerts rows, enqueues immediate rescans, fires webhooks and emails.
 *     Alerts are deduplicated per (subscription, CVE), which is what makes an
 *     hourly cadence with an overlapping lookback window safe.
 *
 *  4. monitor-cert-expiry  (daily 07:00 UTC)
 *     A safety net behind the pulse check. Reads the newest live certificate
 *     reading, falling back to the most recent scan report, and alerts at ≤30,
 *     ≤14, ≤7 days — each threshold once per certificate cycle.
 *
 * The split between 1 and 2 is the whole design: a full rescan is expensive
 * enough to schedule in days, so it cannot be what tells a user their site is
 * down. A pulse is cheap enough to run every hour, so it can.
 */

import { getBoss } from "./queue";
import { logger } from "./logger";
import { SWEEP_QUEUE, runSweep } from "./monitorSchedulerSweep";
import { PULSE_QUEUE, runPulseCheck } from "./monitorSchedulerPulse";
import { CVE_QUEUE, runCveCheck } from "./monitorSchedulerCve";
import { CERT_QUEUE, runCertExpiryCheck } from "./monitorSchedulerCert";
export { nextScanDelayDays, computeNextScanAt, isSubscriptionDue, activeEntitledSubscriptions } from "./monitorSchedulerSweep";
export { selectNewCveMatches } from "./monitorSchedulerCve";

// ─── Scheduler registration ───────────────────────────────────────────────────

export async function startMonitorScheduler(): Promise<void> {
  const boss = await getBoss();

  await boss.createQueue(SWEEP_QUEUE);
  await boss.createQueue(PULSE_QUEUE);
  await boss.createQueue(CVE_QUEUE);
  await boss.createQueue(CERT_QUEUE);

  // Every 6 hours
  await boss.schedule(SWEEP_QUEUE, "0 */6 * * *", {});
  // Hourly, at :20 — offset from the sweep and the CVE check so the three jobs
  // do not all start work on the same minute.
  await boss.schedule(PULSE_QUEUE, "20 * * * *", {});
  // Hourly, at :05. Was daily at 06:00; a CVE that matched a customer's stack
  // could sit unreported for most of a day.
  await boss.schedule(CVE_QUEUE, "5 * * * *", {});
  // Daily 07:00 UTC
  await boss.schedule(CERT_QUEUE, "0 7 * * *", {});

  await boss.work(SWEEP_QUEUE, async () => { await runSweep(); });
  await boss.work(PULSE_QUEUE, async () => { await runPulseCheck(); });
  await boss.work(CVE_QUEUE, async () => { await runCveCheck(); });
  await boss.work(CERT_QUEUE, async () => { await runCertExpiryCheck(); });

  logger.info(
    "Monitor scheduler registered (adaptive sweep 6h + hourly pulse + hourly CVE + daily cert expiry)",
  );
}
/**
 * Monitor Scheduler — 2026 continuous monitoring standard.
 *
 * Jobs:
 *  1. monitor-sweep  (every 6 h) — risk-adaptive rescan sweep
 *     Replaces the fixed Sunday-only weekly scan. After each scan completes,
 *     nextScanAt is set based on the resulting grade (A→14d, B/C→7d, D/F→3d).
 *     This sweep finds all subscriptions where nextScanAt ≤ now and enqueues them.
 *
 *  2. monitor-cve-check  (daily 06:00 UTC)
 *     Fetches CVEs from NVD, matches them against each active subscription's tech
 *     stack, enriches matches with EPSS scores from api.first.org, creates
 *     cve_alerts rows, enqueues immediate rescans, fires webhooks and emails.
 *
 *  3. monitor-cert-expiry  (daily 07:00 UTC)
 *     Checks TLS certificate expiry dates stored in the most recent scan report's
 *     rawData. Fires alerts at ≤30, ≤14, ≤7 days (each threshold once per cert cycle).
 */

import { getBoss } from "./queue";
import {
  db,
  monitorSubscriptionsTable,
  cveAlertsTable,
  reportsTable,
  scansTable,
  certExpiryAlertsTable,
} from "@workspace/db";
import { eq, and, lte, desc, isNull, or } from "drizzle-orm";
import { enqueueScan } from "./queue";
import { logger } from "./logger";
import { fetchRecentCves, matchCvesToTechnologies } from "./cveMonitor";
import {
  sendMonitorCveAlertEmail,
  sendMonitorScanQueuedEmail,
  sendRegressionAlertEmail,
  sendCertExpiryEmail,
} from "./mailer";
import { fireWebhook } from "./webhook";

const SWEEP_QUEUE      = "monitor-sweep";
const CVE_QUEUE        = "monitor-cve-check";
const CERT_QUEUE       = "monitor-cert-expiry";

// ─── Cadence helpers ──────────────────────────────────────────────────────────

export function nextScanDelayDays(grade: string): number {
  if (grade === "A") return 14;
  if (grade === "B" || grade === "C") return 7;
  return 3; // D or F
}

export function computeNextScanAt(grade: string, from: Date = new Date()): Date {
  const days = nextScanDelayDays(grade);
  return new Date(from.getTime() + days * 24 * 60 * 60 * 1000);
}

// ─── EPSS enrichment ──────────────────────────────────────────────────────────

interface EpssEntry { cve: string; epss: string; percentile: string }

async function fetchEpssScores(
  cveIds: string[],
): Promise<Map<string, { score: number; percentile: number }>> {
  if (cveIds.length === 0) return new Map();
  const log = logger.child({ job: "epss-fetch" });

  try {
    const url = `https://api.first.org/data/json?cve=${cveIds.join(",")}`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(15_000),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`EPSS API ${res.status}`);

    const json = (await res.json()) as { data?: EpssEntry[] };
    const map = new Map<string, { score: number; percentile: number }>();
    for (const entry of json.data ?? []) {
      map.set(entry.cve, {
        score: parseFloat(entry.epss),
        percentile: parseFloat(entry.percentile),
      });
    }
    log.info({ fetched: map.size }, "EPSS scores fetched");
    return map;
  } catch (err) {
    log.warn({ err }, "EPSS fetch failed (non-fatal)");
    return new Map();
  }
}

// ─── Helper: enqueue a monitor scan ──────────────────────────────────────────

async function enqueueMonitorScan(sub: {
  id: string;
  userId: string;
  userEmail: string;
  targetUrl: string;
}, reason: "adaptive" | "cve"): Promise<string | null> {
  try {
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId: sub.userId,
        userEmail: sub.userEmail,
        targetUrl: sub.targetUrl,
        tier: "deep",
        status: "paid",
      })
      .returning();

    await enqueueScan({
      scanId: scan.id,
      userId: sub.userId,
      targetUrl: sub.targetUrl,
      tier: "deep",
      monitorSubscriptionId: sub.id,
    });

    await db
      .update(scansTable)
      .set({ status: "queued", startedAt: new Date() })
      .where(eq(scansTable.id, scan.id));

    return scan.id;
  } catch (err) {
    logger.error({ err, subscriptionId: sub.id }, "Failed to enqueue monitor scan");
    return null;
  }
}

// ─── 1. Sweep job ─────────────────────────────────────────────────────────────

async function runSweep(): Promise<void> {
  const log = logger.child({ job: SWEEP_QUEUE });
  const now = new Date();
  log.info("Running adaptive scan sweep");

  const subscriptions = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.status, "active"));

  const due = subscriptions.filter((sub) => {
    if (sub.expiresAt <= now) return false;
    if (!sub.nextScanAt) {
      // No nextScanAt set yet — schedule if also no lastScanAt, or lastScanAt > 7 days ago
      if (!sub.lastScanAt) return true;
      return sub.lastScanAt.getTime() < now.getTime() - 7 * 24 * 60 * 60 * 1000;
    }
    return sub.nextScanAt <= now;
  });

  log.info({ total: subscriptions.length, due: due.length }, "Subscriptions due for rescan");

  const appOrigin = process.env.APP_ORIGIN ?? "https://seclayer.io";

  for (const sub of due) {
    const scanId = await enqueueMonitorScan(sub, "adaptive");
    if (!scanId) continue;

    log.info({ subscriptionId: sub.id, scanId, targetUrl: sub.targetUrl }, "Adaptive rescan queued");

    if (sub.userEmail) {
      await sendMonitorScanQueuedEmail({
        toEmail: sub.userEmail,
        targetUrl: sub.targetUrl,
        scanId,
        reason: "adaptive",
        dashboardUrl: `${appOrigin}/monitor`,
      });
    }

    if (sub.webhookUrl) {
      await fireWebhook(sub.webhookUrl, "scan_complete", sub.targetUrl, sub.id, {
        scanId,
        reason: "adaptive",
      });
    }
  }
}

// ─── 2. CVE check job ─────────────────────────────────────────────────────────

async function runCveCheck(): Promise<void> {
  const log = logger.child({ job: CVE_QUEUE });
  log.info("Running daily CVE check");

  const now = new Date();
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  const cves = await fetchRecentCves(yesterday, now);
  log.info({ cveCount: cves.length }, "Fetched CVEs from NVD");
  if (cves.length === 0) return;

  const activeSubscriptions = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.status, "active"));

  const validSubs = activeSubscriptions.filter((s) => s.expiresAt > now);
  log.info({ subscriptions: validSubs.length }, "Checking active subscriptions against CVEs");

  const appOrigin = process.env.APP_ORIGIN ?? "https://seclayer.io";

  for (const sub of validSubs) {
    try {
      const [latestReport] = await db
        .select({ id: reportsTable.id, data: reportsTable.data })
        .from(reportsTable)
        .where(
          and(
            eq(reportsTable.userId, sub.userId),
            eq(reportsTable.targetUrl, sub.targetUrl),
          ),
        )
        .orderBy(desc(reportsTable.createdAt))
        .limit(1);

      if (!latestReport) continue;

      const reportData = latestReport.data as { technologies?: string[] };
      const technologies = reportData.technologies ?? [];
      if (technologies.length === 0) continue;

      const matches = matchCvesToTechnologies(technologies, cves);
      if (matches.length === 0) continue;

      log.info(
        { subscriptionId: sub.id, targetUrl: sub.targetUrl, matches: matches.length },
        "CVE matches found — enriching with EPSS and triggering rescan",
      );

      // Fetch EPSS scores for all matched CVEs
      const cveIds = matches.map(({ cve }) => cve.id);
      const epssMap = await fetchEpssScores(cveIds);

      // Enqueue immediate rescan
      const scanId = await enqueueMonitorScan(sub, "cve");

      // Schedule a 24h follow-up rescan: set nextScanAt = now + 24h so the adaptive
      // sweep will pick it up again 24 hours after the CVE-triggered scan.
      await db
        .update(monitorSubscriptionsTable)
        .set({ nextScanAt: new Date(Date.now() + 24 * 60 * 60 * 1000) })
        .where(eq(monitorSubscriptionsTable.id, sub.id));

      // Insert CVE alerts sorted by EPSS score descending
      const sortedMatches = [...matches].sort((a, b) => {
        const epssA = epssMap.get(a.cve.id)?.score ?? 0;
        const epssB = epssMap.get(b.cve.id)?.score ?? 0;
        return epssB - epssA;
      });

      for (const { cve, matchedTech } of sortedMatches) {
        const epss = epssMap.get(cve.id);
        await db.insert(cveAlertsTable).values({
          subscriptionId: sub.id,
          cveId: cve.id,
          cveSummary: cve.description.slice(0, 500),
          affectedTech: matchedTech,
          severity: cve.severity,
          epssScore: epss?.score ?? null,
          epssPercentile: epss?.percentile ?? null,
          triggerScanId: scanId ?? undefined,
        });
      }

      // Email
      if (sub.userEmail) {
        await sendMonitorCveAlertEmail({
          toEmail: sub.userEmail,
          targetUrl: sub.targetUrl,
          cveMatches: sortedMatches.map(({ cve, matchedTech }) => ({
            cveId: cve.id,
            summary: cve.description.slice(0, 200),
            severity: cve.severity,
            affectedTech: matchedTech,
          })),
          scanId: scanId ?? "",
          dashboardUrl: `${appOrigin}/monitor`,
        });
      }

      // Webhook
      if (sub.webhookUrl) {
        await fireWebhook(sub.webhookUrl, "cve_alert", sub.targetUrl, sub.id, {
          cves: sortedMatches.map(({ cve, matchedTech }) => {
            const epss = epssMap.get(cve.id);
            return {
              cveId: cve.id,
              severity: cve.severity,
              affectedTech: matchedTech,
              epssScore: epss?.score,
              epssPercentile: epss?.percentile,
            };
          }),
          scanId,
        });
      }
    } catch (err) {
      log.error({ err, subscriptionId: sub.id }, "CVE check failed for subscription");
    }
  }
}

// ─── 3. Certificate expiry job ────────────────────────────────────────────────

const CERT_THRESHOLDS = [30, 14, 7] as const;

async function runCertExpiryCheck(): Promise<void> {
  const log = logger.child({ job: CERT_QUEUE });
  log.info("Running daily certificate expiry check");

  const now = new Date();

  const activeSubscriptions = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.status, "active"));

  const validSubs = activeSubscriptions.filter((s) => s.expiresAt > now);
  log.info({ subscriptions: validSubs.length }, "Checking cert expiry for active subscriptions");

  const appOrigin = process.env.APP_ORIGIN ?? "https://seclayer.io";

  for (const sub of validSubs) {
    try {
      // Look for cert expiry date in the most recent report's rawData
      const [latestReport] = await db
        .select({ data: reportsTable.data })
        .from(reportsTable)
        .where(
          and(
            eq(reportsTable.userId, sub.userId),
            eq(reportsTable.targetUrl, sub.targetUrl),
          ),
        )
        .orderBy(desc(reportsTable.createdAt))
        .limit(1);

      if (!latestReport) continue;

      // SSL Labs stores cert expiry in report data under tlsGrade section
      const reportData = latestReport.data as {
        tlsGrade?: string;
        certExpiry?: string | null;
        rawData?: { certExpiry?: string | null };
      };

      // Extract cert expiry — stored by the scanner when SSL Labs returns cert info
      const certExpiryRaw =
        reportData.certExpiry ??
        reportData.rawData?.certExpiry ??
        null;

      if (!certExpiryRaw) continue;

      const expiryDate = new Date(certExpiryRaw);
      if (isNaN(expiryDate.getTime())) continue;

      const daysRemaining = Math.ceil((expiryDate.getTime() - now.getTime()) / 86_400_000);
      if (daysRemaining <= 0 || daysRemaining > 30) continue;

      // Check each threshold
      for (const threshold of CERT_THRESHOLDS) {
        if (daysRemaining > threshold) continue;

        // Check if we already sent an alert for this threshold + cert cycle
        // Must include expiryDate so alerts re-fire when the cert is renewed (new cycle = new expiry date)
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

        if (existing.length > 0) continue; // already alerted at this threshold for this cert cycle

        // Insert alert record
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

        // Email
        if (sub.userEmail) {
          await sendCertExpiryEmail({
            toEmail: sub.userEmail,
            targetUrl: sub.targetUrl,
            daysRemaining,
            expiryDate,
            dashboardUrl: `${appOrigin}/monitor`,
          });
        }

        // Webhook
        if (sub.webhookUrl) {
          await fireWebhook(sub.webhookUrl, "cert_expiry", sub.targetUrl, sub.id, {
            daysRemaining,
            expiryDate: expiryDate.toISOString(),
            alertThreshold: threshold,
          });
        }

        break; // Only fire one threshold per run (the lowest applicable one)
      }
    } catch (err) {
      log.error({ err, subscriptionId: sub.id }, "Cert expiry check failed for subscription");
    }
  }
}

// ─── Scheduler registration ───────────────────────────────────────────────────

export async function startMonitorScheduler(): Promise<void> {
  const boss = await getBoss();

  await boss.createQueue(SWEEP_QUEUE);
  await boss.createQueue(CVE_QUEUE);
  await boss.createQueue(CERT_QUEUE);

  // Every 6 hours
  await boss.schedule(SWEEP_QUEUE, "0 */6 * * *", {});
  // Daily 06:00 UTC
  await boss.schedule(CVE_QUEUE, "0 6 * * *", {});
  // Daily 07:00 UTC
  await boss.schedule(CERT_QUEUE, "0 7 * * *", {});

  await boss.work(SWEEP_QUEUE, async () => { await runSweep(); });
  await boss.work(CVE_QUEUE, async () => { await runCveCheck(); });
  await boss.work(CERT_QUEUE, async () => { await runCertExpiryCheck(); });

  logger.info("Monitor scheduler registered (adaptive sweep 6h + daily CVE + daily cert expiry)");
}


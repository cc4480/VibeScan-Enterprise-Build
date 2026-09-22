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
import {
  db,
  monitorSubscriptionsTable,
  cveAlertsTable,
  reportsTable,
  scansTable,
  certExpiryAlertsTable,
  monitorPulseChecksTable,
} from "@workspace/db";
import { eq, and, lte, lt, desc, isNull, or, inArray } from "drizzle-orm";
import { enqueueScan } from "./queue";
import { logger } from "./logger";
import { fetchRecentCves, matchCvesToTechnologies } from "./cveMonitor";
import {
  sendMonitorCveAlertEmail,
  sendMonitorScanQueuedEmail,
  sendRegressionAlertEmail,
  sendCertExpiryEmail,
  sendAvailabilityEmail,
  sendDriftEmail,
} from "./mailer";
import { fireWebhook } from "./webhook";
import { APP_ORIGIN } from "./appOrigin";
import { monitorEntitlement } from "./entitlements";
import { highestSeverity } from "./notificationPrefs";
import {
  runPulse,
  evaluateAvailability,
  evaluateDrift,
  certDaysRemaining,
  PULSE_RETENTION_DAYS,
  DOWN_THRESHOLD,
  type HstsBucket,
} from "./monitorPulse";

const SWEEP_QUEUE      = "monitor-sweep";
const PULSE_QUEUE      = "monitor-pulse";
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

/**
 * Whether the sweep should enqueue a rescan for this subscription right now.
 * This is the one decision that makes monitoring "automatic" — get it wrong
 * in one direction and paying customers stop being rescanned; get it wrong in
 * the other and the same subscription gets enqueued twice in one sweep tick.
 *
 * Pulled out of runSweep as its own pure function specifically so it can be
 * tested without standing up the db, the queue and the mailer — the sweep body
 * itself had zero tests before this, despite deciding when every automatic
 * scan in the product fires.
 */
export function isSubscriptionDue(
  sub: { expiresAt: Date; nextScanAt: Date | null; lastScanAt: Date | null },
  now: Date = new Date(),
): boolean {
  if (sub.expiresAt <= now) return false;
  if (!sub.nextScanAt) {
    // No cadence set yet — this is the brand-new-subscription and the
    // legacy-row shape. Treat "never scanned" as due (the baseline scan)
    // and otherwise fall back to a 7-day floor so a row that predates
    // nextScanAt being written on every path doesn't wait forever.
    if (!sub.lastScanAt) return true;
    return sub.lastScanAt.getTime() < now.getTime() - 7 * 24 * 60 * 60 * 1000;
  }
  return sub.nextScanAt <= now;
}

// ─── Shared subscription selection ────────────────────────────────────────────

type ActiveSub = typeof monitorSubscriptionsTable.$inferSelect;

/**
 * Every active, unexpired subscription whose owner is still entitled to
 * monitoring.
 *
 * Entitlement is resolved per USER, not per subscription, so an agency with
 * forty monitored sites costs one lookup rather than forty. Inert until
 * MONITORING_REQUIRES_PLAN is set, where monitorEntitlement short-circuits
 * before touching the database at all.
 *
 * Shared by all four jobs because they were drifting: the sweep checked
 * entitlement and the CVE and certificate jobs did not, so a lapsed account
 * would have stopped being rescanned while still receiving alerts about the
 * scans it was no longer getting.
 */
async function activeEntitledSubscriptions(
  now: Date,
): Promise<{ subs: ActiveSub[]; total: number; skippedUnentitled: number }> {
  const all = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.status, "active"));

  const unexpired = all.filter((sub) => sub.expiresAt > now);

  const entitlementByUser = new Map<string, boolean>();
  const subs: ActiveSub[] = [];
  let skippedUnentitled = 0;

  for (const sub of unexpired) {
    let allowed = entitlementByUser.get(sub.userId);
    if (allowed === undefined) {
      allowed = (await monitorEntitlement(sub.userId)).monitoringActive;
      entitlementByUser.set(sub.userId, allowed);
    }
    if (allowed) subs.push(sub);
    else skippedUnentitled++;
  }

  return { subs, total: all.length, skippedUnentitled };
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
        origin: "monitor",
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

  const { subs, total, skippedUnentitled } = await activeEntitledSubscriptions(now);
  const due = subs.filter((sub) => isSubscriptionDue(sub, now));

  log.info({ total, due: due.length, skippedUnentitled }, "Subscriptions due for rescan");

  const appOrigin = APP_ORIGIN;

  for (const sub of due) {
    // Advance nextScanAt to a sentinel (minimum cadence = 3 days) before enqueueing
    // so that the next 6h sweep does not double-pick this subscription while the
    // job is still in-flight. Worker will overwrite with the accurate grade-based value.
    await db
      .update(monitorSubscriptionsTable)
      .set({ nextScanAt: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000) })
      .where(eq(monitorSubscriptionsTable.id, sub.id));

    const scanId = await enqueueMonitorScan(sub, "adaptive");
    if (!scanId) continue;

    log.info({ subscriptionId: sub.id, scanId, targetUrl: sub.targetUrl }, "Adaptive rescan queued");

    if (sub.userEmail) {
      await sendMonitorScanQueuedEmail({
        toEmail: sub.userEmail,
        userId: sub.userId,
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
      }, { userId: sub.userId });
    }
  }
}

// ─── 2. Hourly pulse job ──────────────────────────────────────────────────────

/**
 * How many sites are probed at once.
 *
 * Kept low on purpose. These requests go to other people's production servers,
 * and a monitoring product that arrives as a burst of simultaneous traffic every
 * hour is a nuisance at best and looks like an attack at worst.
 */
const PULSE_CONCURRENCY = 5;

/** What one pulse did, so the run can summarise instead of logging nothing. */
interface PulseOutcome {
  reachable: boolean;
  availabilityAlert: boolean;
  driftFindings: number;
}

async function pulseOne(sub: ActiveSub, appOrigin: string): Promise<PulseOutcome> {
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
    await maybeAlertCertExpiry(sub, result.certExpiresAt, checkedAt, appOrigin, log);
  }

  return outcome;
}

async function runPulseCheck(): Promise<void> {
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

// ─── 3. CVE check job ─────────────────────────────────────────────────────────

/**
 * How far back the hourly CVE check looks.
 *
 * Longer than the hour between runs, deliberately. NVD populates a CVE's
 * published timestamp before it appears in the feed, so a window that exactly
 * matched the schedule would drop anything that landed in the seam. The overlap
 * is only safe because alerts are deduplicated per (subscription, CVE) — see
 * below.
 */
const CVE_LOOKBACK_MS = 3 * 60 * 60 * 1000;

/**
 * Which of this run's CVE matches are genuinely new for one subscription.
 *
 * This is the only thing making an hourly CVE check possible. The lookback
 * window deliberately overlaps the schedule, so the same CVE matches on several
 * consecutive runs; without this the user gets the same alert every hour and a
 * full rescan with it.
 *
 * It also collapses duplicates WITHIN a single run. One CVE can match two
 * technologies on the same site — "nginx" and "nginx 1.24", say — and the
 * already-alerted set is read from the database before any of this run's rows
 * are written, so a repeat inside one batch would slip past a database check
 * entirely and be inserted twice. The first match wins, because
 * matchCvesToTechnologies returns the most specific technology first.
 *
 * Pure and exported for tests: an off-by-one here is not a crash, it is a
 * customer receiving twenty-four identical emails a day.
 */
export function selectNewCveMatches<T extends { cve: { id: string } }>(
  matches: T[],
  alreadyAlerted: Iterable<string>,
): T[] {
  const seen = new Set(alreadyAlerted);
  const fresh: T[] = [];

  for (const match of matches) {
    if (seen.has(match.cve.id)) continue;
    seen.add(match.cve.id);
    fresh.push(match);
  }

  return fresh;
}

async function runCveCheck(): Promise<void> {
  const log = logger.child({ job: CVE_QUEUE });
  log.info("Running CVE check");

  const now = new Date();
  const since = new Date(now.getTime() - CVE_LOOKBACK_MS);

  const cves = await fetchRecentCves(since, now);
  log.info({ cveCount: cves.length, lookbackHours: CVE_LOOKBACK_MS / 3_600_000 }, "Fetched CVEs from NVD");
  if (cves.length === 0) return;

  const { subs: validSubs, total, skippedUnentitled } = await activeEntitledSubscriptions(now);
  log.info(
    { total, subscriptions: validSubs.length, skippedUnentitled },
    "Checking active subscriptions against CVEs",
  );

  const appOrigin = APP_ORIGIN;

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

      const allMatches = matchCvesToTechnologies(technologies, cves);
      if (allMatches.length === 0) continue;

      // Drop anything this subscription has already been told about.
      //
      // This is what makes an hourly cadence possible at all. The lookback
      // window overlaps the schedule by design, so the same CVE matches on
      // several consecutive runs; without this the user would get the same
      // alert every hour and a rescan every hour with it. Keyed on the
      // subscription, not the user, because two monitored sites can genuinely
      // both be affected by one CVE.
      const seen = await db
        .select({ cveId: cveAlertsTable.cveId })
        .from(cveAlertsTable)
        .where(
          and(
            eq(cveAlertsTable.subscriptionId, sub.id),
            inArray(cveAlertsTable.cveId, allMatches.map(({ cve }) => cve.id)),
          ),
        );

      const matches = selectNewCveMatches(allMatches, seen.map((row) => row.cveId));

      if (matches.length === 0) {
        log.debug(
          { subscriptionId: sub.id, alreadyAlerted: seen.length },
          "CVE matches all previously alerted — nothing to do",
        );
        continue;
      }

      log.info(
        {
          subscriptionId: sub.id,
          targetUrl: sub.targetUrl,
          matches: matches.length,
          suppressedAsDuplicate: allMatches.length - matches.length,
        },
        "New CVE matches found — enriching with EPSS and triggering rescan",
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

      // Insert CVE alerts sorted by EPSS × severity_weight descending
      const SEVERITY_WEIGHT: Record<string, number> = {
        CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
      };
      const combinedScore = (cveId: string, severity: string) =>
        (epssMap.get(cveId)?.score ?? 0) * (SEVERITY_WEIGHT[severity?.toUpperCase()] ?? 1);

      const sortedMatches = [...matches].sort((a, b) =>
        combinedScore(b.cve.id, b.cve.severity) - combinedScore(a.cve.id, a.cve.severity),
      );

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
          userId: sub.userId,
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
        }, {
          userId: sub.userId,
          // The worst CVE in the batch. Judging by the first would drop a mail
          // containing a critical because it happened to lead with a low.
          severity: highestSeverity(sortedMatches.map(({ cve }) => ({ severity: cve.severity }))),
        });
      }
    } catch (err) {
      log.error({ err, subscriptionId: sub.id }, "CVE check failed for subscription");
    }
  }
}

// ─── 4. Certificate expiry ────────────────────────────────────────────────────

const CERT_THRESHOLDS = [30, 14, 7] as const;

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
async function maybeAlertCertExpiry(
  sub: Pick<ActiveSub, "id" | "userId" | "userEmail" | "targetUrl" | "webhookUrl">,
  expiryDate: Date,
  now: Date,
  appOrigin: string,
  log: typeof logger,
): Promise<void> {
  if (Number.isNaN(expiryDate.getTime())) return;

  const daysRemaining = Math.ceil((expiryDate.getTime() - now.getTime()) / 86_400_000);
  if (daysRemaining <= 0 || daysRemaining > 30) return;

  for (const threshold of CERT_THRESHOLDS) {
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
async function runCertExpiryCheck(): Promise<void> {
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

      // Newest live reading first — it is at most an hour old.
      const [livePulse] = await db
        .select({ certExpiresAt: monitorPulseChecksTable.certExpiresAt })
        .from(monitorPulseChecksTable)
        .where(
          and(
            eq(monitorPulseChecksTable.subscriptionId, sub.id),
            eq(monitorPulseChecksTable.reachable, true),
          ),
        )
        .orderBy(desc(monitorPulseChecksTable.checkedAt))
        .limit(1);

      if (livePulse?.certExpiresAt) {
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
              eq(reportsTable.targetUrl, sub.targetUrl),
            ),
          )
          .orderBy(desc(reportsTable.createdAt))
          .limit(1);

        if (!latestReport) continue;

        const reportData = latestReport.data as {
          tlsGrade?: string;
          certExpiry?: string | null;
          rawData?: { certExpiry?: string | null };
        };

        const certExpiryRaw = reportData.certExpiry ?? reportData.rawData?.certExpiry ?? null;
        if (!certExpiryRaw) continue;
        expiryDate = new Date(certExpiryRaw);
      }

      if (!expiryDate) continue;
      await maybeAlertCertExpiry(sub, expiryDate, now, appOrigin, log);
    } catch (err) {
      log.error({ err, subscriptionId: sub.id }, "Cert expiry check failed for subscription");
    }
  }
}

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


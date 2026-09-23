import { Router, type IRouter, type Request, type Response, type NextFunction } from "express";
import {
  db, monitorSubscriptionsTable, cveAlertsTable, reportsTable,
  monitorScoreHistoryTable, monitorRegressionsTable, certExpiryAlertsTable,
  monitorPulseChecksTable,
} from "@workspace/db";
import { eq, and, gte, desc, count, sql, inArray } from "drizzle-orm";
import { z } from "zod";
import { enqueueScan } from "../lib/queue";
import { scansTable } from "@workspace/db";
import { logger } from "../lib/logger";
import { checkScanTarget } from "../lib/ssrfGuard";
import { rateLimitMiddleware, scanRateLimitRules } from "../lib/rateLimit";
import { trialScansExhausted, TRIAL_LIMIT_MESSAGE, TRIAL_LIMIT_CODE } from "../lib/freeTrial";
import { monitorEntitlement } from "../lib/entitlements";
import { hasLivePlan, chargeScan, refundCharge, refundFailedScan, type PaidWith } from "../lib/billing";
import { creditBalance } from "../lib/credits";
import { summariseUptime } from "../lib/monitorPulse";

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

/** Fetch the most recent completed report for a user+URL pair. */
async function fetchLatestReport(userId: string, targetUrl: string) {
  const [report] = await db
    .select({
      id: reportsTable.id,
      scannedAt: reportsTable.scannedAt,
      data: reportsTable.data,
    })
    .from(reportsTable)
    .where(and(eq(reportsTable.userId, userId), eq(reportsTable.targetUrl, targetUrl)))
    .orderBy(desc(reportsTable.scannedAt))
    .limit(1);
  return report ?? null;
}

const router: IRouter = Router();

const CreateMonitorBody = z.object({
  targetUrl: z.string().url("Must be a valid URL"),
  webhookUrl: z.string().url().optional(),
});

// ── POST /api/monitor/subscriptions ──────────────────────────────────────────
// Create a new monitoring subscription for a URL.
// Free unless MONITORING_REQUIRES_PLAN is on; then it needs SecScan Pro (see lib/entitlements.ts).

// A subscription schedules recurring scans, so it draws on the same budget.
// Per user, for the same reason as the scan route: this was IP-keyed, so
// colleagues on one office egress shared a single allowance.
const monitorRateLimit = rateLimitMiddleware({
  rules: scanRateLimitRules(),
  name: "monitor-subscriptions",
  keyFrom: (req) => (req.isAuthenticated() ? `user:${req.user.id}` : undefined),
});

// Auth first, so an unauthenticated caller cannot spend a real user's budget.
function requireMonitorAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

router.post("/monitor/subscriptions", requireMonitorAuth, monitorRateLimit, async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CreateMonitorBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Invalid request" });
    return;
  }

  const { targetUrl, webhookUrl } = parsed.data;

  // A Pro subscriber is PAYING for monitoring: they may add sites whatever
  // happened to their free scans. Without a plan, adding a site fires a
  // baseline deep scan that is charged like any other scan (below): a free
  // scan, else a credit. This refuses early only when neither is left — it
  // used to refuse whenever the free scans were gone, so a customer holding
  // credits could not add a single monitor.
  const planHolder = await hasLivePlan(req.user.id);
  if (!planHolder && (await trialScansExhausted(req.user.id)) && (await creditBalance(req.user.id)) <= 0) {
    res.status(403).json({ error: TRIAL_LIMIT_MESSAGE, code: TRIAL_LIMIT_CODE });
    return;
  }

  // How many sites this user's plan covers. Inert until
  // MONITORING_REQUIRES_PLAN is set — see lib/entitlements.ts — so today this
  // resolves to "unlimited" and refuses nobody.
  const entitlement = await monitorEntitlement(req.user.id);
  if (!entitlement.monitoringActive) {
    res.status(403).json({
      error:
        entitlement.reason === "paused"
          ? "Monitoring is paused while your plan is unpaid. Your history is still here."
          : "Monitoring needs an active plan.",
      code: "monitor_plan_required",
      reason: entitlement.reason,
    });
    return;
  }

  // Counted rather than trusted from the plan: a limit lowered on a downgrade,
  // or a row added by an admin, must both be reflected without a backfill.
  const [{ value: activeCount }] = await db
    .select({ value: count() })
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.userId, req.user.id),
        eq(monitorSubscriptionsTable.status, "active"),
      ),
    );

  if (Number(activeCount) >= entitlement.urlLimit) {
    res.status(403).json({
      error: `Your plan covers ${entitlement.urlLimit} monitored site${entitlement.urlLimit === 1 ? "" : "s"}. Upgrade or stop monitoring one to add another.`,
      code: "monitor_url_limit",
      urlLimit: entitlement.urlLimit,
      monitoring: Number(activeCount),
    });
    return;
  }

  // Same guard as POST /scans — a subscription schedules recurring scans, so
  // an internal target here is the SSRF hole on a 3-to-14-day timer.
  const targetCheck = await checkScanTarget(targetUrl);
  if (!targetCheck.ok) {
    res.status(400).json({ error: targetCheck.reason ?? "Invalid URL." });
    return;
  }

  // Check for an existing active subscription for this user+URL
  const [existing] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.userId, req.user.id),
        eq(monitorSubscriptionsTable.targetUrl, targetUrl),
        eq(monitorSubscriptionsTable.status, "active"),
      ),
    );

  if (existing) {
    res.status(409).json({ error: "You already have an active monitor subscription for this URL." });
    return;
  }

  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setFullYear(expiresAt.getFullYear() + 1);

  // Seed from the most recent existing report for this URL so the card
  // immediately shows the last grade/scan date instead of "Never".
  const existingReport = await fetchLatestReport(req.user.id, targetUrl);
  const seedReportId = existingReport?.id ?? null;
  const seedScanAt = existingReport?.scannedAt ?? null;

  // Charged last, after every check that could still refuse, so a refusal
  // never costs a scan. Charged before the insert, so two concurrent requests
  // cannot both ride on the last scan left.
  let baselinePaidWith: PaidWith | null = null;
  if (!planHolder) {
    baselinePaidWith = await chargeScan(req.user.id);
    if (baselinePaidWith === null) {
      res.status(403).json({ error: TRIAL_LIMIT_MESSAGE, code: TRIAL_LIMIT_CODE });
      return;
    }
  }

  let sub: typeof monitorSubscriptionsTable.$inferSelect;
  try {
    [sub] = await db
    .insert(monitorSubscriptionsTable)
    .values({
      userId: req.user.id,
      userEmail: req.user.email ?? "",
      targetUrl,
      status: "active",
      expiresAt,
      lastReportId: seedReportId,
      lastScanAt: seedScanAt,
      // Same sentinel the sweep itself writes before enqueueing (see
      // monitorScheduler.ts) — the worker overwrites it with the real
      // grade-based value once the baseline scan below completes. Leaving
      // this null, as before, meant a subscription with no lastScanAt read
      // as "due" to the sweep's own eyes: if the 6-hourly sweep ticked
      // before this baseline scan finished, it enqueued a second one for
      // the same subscription. Setting it here closes that race the same
      // way the sweep already closes it against itself.
      nextScanAt: new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000),
      webhookUrl: webhookUrl ?? null,
    })
    .returning();
  } catch (err) {
    await refundCharge(req.user.id, baselinePaidWith);
    throw err;
  }

  // Always trigger a baseline deep scan immediately on subscription activation.
  // The card is already seeded with the most recent report above so it shows
  // historical data while the new scan runs.
  let baselineScanId: string | null = null;
  try {
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId: req.user.id,
        userEmail: req.user.email ?? "",
        targetUrl,
        tier: "deep",
        status: "paid",
        origin: "monitor",
        // Covered by the plan for a subscriber. Otherwise whatever
        // chargeScan took above — it used to spend nothing, so a free user
        // could add monitors one after another and collect a full scan from
        // each.
        paidWith: baselinePaidWith,
      })
      .returning();
    baselineScanId = scan.id;

    await enqueueScan({
      scanId: scan.id,
      userId: req.user.id,
      targetUrl,
      tier: "deep",
      monitorSubscriptionId: sub.id,
    });

    await db
      .update(scansTable)
      .set({ status: "queued", startedAt: new Date() })
      .where(eq(scansTable.id, scan.id));

    logger.info({ subscriptionId: sub.id, scanId: scan.id }, "Initial monitor scan queued");

    res.status(201).json({
      subscription: sub,
      initialScanId: scan.id,
    });
  } catch (err) {
    logger.error({ err }, "Failed to enqueue initial monitor scan");
    // The monitor stays (the sweep will scan it), but this scan never ran:
    // give its charge back, the same way as a manual scan that fails to queue.
    try {
      if (baselineScanId) {
        await db.update(scansTable).set({ status: "failed", error: "Could not be queued" }).where(eq(scansTable.id, baselineScanId));
        await refundFailedScan(baselineScanId);
      } else {
        await refundCharge(req.user.id, baselinePaidWith);
      }
    } catch (refundErr) {
      logger.error({ err: refundErr }, "Could not refund a baseline monitor scan that failed to queue");
    }
    res.status(201).json({ subscription: sub, initialScanId: null });
  }
});

// ── GET /api/monitor/subscriptions ───────────────────────────────────────────
// List all monitor subscriptions for the authenticated user.

router.get("/monitor/subscriptions", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subs = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(eq(monitorSubscriptionsTable.userId, req.user.id))
    .orderBy(desc(monitorSubscriptionsTable.createdAt));

  // Attach latest report info and alert count to each subscription
  const enriched = await Promise.all(
    subs.map(async (sub) => {
      // Resolve the report: prefer lastReportId, fall back to most-recent report for the URL
      let resolvedReport: { id: string; scannedAt: Date; data: unknown } | null = null;

      if (sub.lastReportId) {
        const [r] = await db
          .select({ id: reportsTable.id, scannedAt: reportsTable.scannedAt, data: reportsTable.data })
          .from(reportsTable)
          .where(eq(reportsTable.id, sub.lastReportId));
        resolvedReport = r ?? null;
      }

      // Fallback: look up the most recent report for this user+URL
      if (!resolvedReport) {
        resolvedReport = await fetchLatestReport(sub.userId, sub.targetUrl);
        // If we found one via fallback, backfill the subscription row so future
        // calls use the fast path.
        if (resolvedReport) {
          await db
            .update(monitorSubscriptionsTable)
            .set({
              lastReportId: resolvedReport.id,
              lastScanAt: resolvedReport.scannedAt,
            })
            .where(eq(monitorSubscriptionsTable.id, sub.id));
        }
      }

      let lastReport: { id: string; grade: string | null; riskScore: number | null } | null = null;
      if (resolvedReport) {
        const data = resolvedReport.data as { summary?: { grade?: string; riskScore?: number } };
        lastReport = {
          id: resolvedReport.id,
          grade: data.summary?.grade ?? null,
          riskScore: data.summary?.riskScore ?? null,
        };
      }

      // Count CVE alerts
      const [{ value: alertCount }] = await db
        .select({ value: count() })
        .from(cveAlertsTable)
        .where(eq(cveAlertsTable.subscriptionId, sub.id));

      // Count regressions from the most recent scan only
      const [latestHistory] = await db
        .select({ scanId: monitorScoreHistoryTable.scanId })
        .from(monitorScoreHistoryTable)
        .where(eq(monitorScoreHistoryTable.subscriptionId, sub.id))
        .orderBy(desc(monitorScoreHistoryTable.scannedAt))
        .limit(1);

      let regressionCount = 0;
      if (latestHistory?.scanId) {
        const [{ value }] = await db
          .select({ value: count() })
          .from(monitorRegressionsTable)
          .where(
            and(
              eq(monitorRegressionsTable.subscriptionId, sub.id),
              eq(monitorRegressionsTable.scanId, latestHistory.scanId),
            ),
          );
        regressionCount = Number(value);
      }

      // Check for cert expiry from most recent cert_expiry_alerts
      const [latestCertAlert] = await db
        .select({ daysRemaining: certExpiryAlertsTable.daysRemaining })
        .from(certExpiryAlertsTable)
        .where(eq(certExpiryAlertsTable.subscriptionId, sub.id))
        .orderBy(desc(certExpiryAlertsTable.sentAt))
        .limit(1);

      const certExpiryDays = latestCertAlert?.daysRemaining ?? null;

      // Whether a scan for this target is running right now.
      //
      // Without this the card had no way to know, so it showed the values from
      // before the scan and never changed: a subscription created seconds ago
      // read "Last scan: Never" while its baseline scan was already finishing,
      // and nothing refetched. A working product that looks broken is worse
      // than a broken one, because there is no reason to trust it afterwards.
      //
      // Matched on user + target rather than a subscription id because scans
      // deliberately carry no foreign key to a subscription (see scansTable) —
      // a scan is a historical record that outlives the subscription.
      const [inFlight] = await db
        .select({ id: scansTable.id, status: scansTable.status })
        .from(scansTable)
        .where(
          and(
            eq(scansTable.userId, sub.userId),
            eq(scansTable.targetUrl, sub.targetUrl),
            inArray(scansTable.status, ["queued", "scanning", "analyzing"]),
          ),
        )
        .orderBy(desc(scansTable.createdAt))
        .limit(1);

      // The hourly pulse. This is what the dashboard shows between scans: the
      // grade may be eleven days old, but "checked 12 minutes ago, answering in
      // 180ms, certificate good for 63 days" is current.
      const pulses24h = await db
        .select({
          reachable: monitorPulseChecksTable.reachable,
          responseTimeMs: monitorPulseChecksTable.responseTimeMs,
          checkedAt: monitorPulseChecksTable.checkedAt,
          httpStatus: monitorPulseChecksTable.httpStatus,
          certDaysRemaining: monitorPulseChecksTable.certDaysRemaining,
          failureReason: monitorPulseChecksTable.failureReason,
        })
        .from(monitorPulseChecksTable)
        .where(
          and(
            eq(monitorPulseChecksTable.subscriptionId, sub.id),
            gte(monitorPulseChecksTable.checkedAt, new Date(Date.now() - TWENTY_FOUR_HOURS_MS)),
          ),
        )
        .orderBy(desc(monitorPulseChecksTable.checkedAt));

      const uptime = summariseUptime(pulses24h);
      const newestPulse = pulses24h[0] ?? null;

      // Use the resolved scanAt so the card shows the correct date even before
      // the subscription row was backfilled.
      const lastScanAt = sub.lastScanAt ?? resolvedReport?.scannedAt ?? null;

      return {
        ...sub,
        lastScanAt,
        lastReport,
        alertCount,
        regressionCount: Number(regressionCount),
        // Prefer the live certificate reading over the one recorded when an
        // alert last fired: the alert row only exists inside 30 days, so
        // without this the dashboard could show nothing for a healthy cert.
        certExpiryDays: newestPulse?.certDaysRemaining ?? certExpiryDays,
        scanInProgress: Boolean(inFlight),
        scanStatus: inFlight?.status ?? null,
        lastPulseAt: newestPulse?.checkedAt ?? null,
        pulseReachable: newestPulse?.reachable ?? null,
        pulseStatus: newestPulse?.httpStatus ?? null,
        pulseFailureReason: newestPulse?.failureReason ?? null,
        responseTimeMs: newestPulse?.responseTimeMs ?? null,
        uptime24h: uptime.uptimePct,
        medianResponseMs: uptime.medianResponseMs,
        pulseChecks24h: uptime.checks,
        // Oldest-first, so the card can draw the last day left-to-right without
        // reversing it. Included here rather than fetched per card because the
        // rows are already in hand — one extra query per subscription on page
        // load, to draw a strip, would be a poor trade.
        pulseTimeline: [...pulses24h]
          .reverse()
          .map((p) => ({
            checkedAt: p.checkedAt,
            reachable: p.reachable,
            responseTimeMs: p.responseTimeMs,
          })),
      };
    }),
  );

  res.json(enriched);
});

// ── DELETE /api/monitor/subscriptions/:id ────────────────────────────────────
// Cancel a monitor subscription.

router.delete("/monitor/subscriptions/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  await db
    .update(monitorSubscriptionsTable)
    .set({ status: "cancelled" })
    .where(eq(monitorSubscriptionsTable.id, subId));

  res.json({ success: true });
});

// ── GET /api/monitor/subscriptions/:id/history ───────────────────────────────
// Return all completed reports for the subscription's URL, newest first.

router.get("/monitor/subscriptions/:id/history", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, req.params.id),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  const reports = await db
    .select({
      id: reportsTable.id,
      scanId: reportsTable.scanId,
      scannedAt: reportsTable.scannedAt,
      tier: reportsTable.tier,
      data: reportsTable.data,
    })
    .from(reportsTable)
    .where(
      and(
        eq(reportsTable.userId, req.user.id),
        eq(reportsTable.targetUrl, sub.targetUrl),
      ),
    )
    .orderBy(desc(reportsTable.scannedAt))
    .limit(20);

  const history = reports.map((r) => {
    const data = r.data as {
      summary?: { grade?: string; riskScore?: number; totalVulnerabilities?: number };
    };
    return {
      id: r.id,
      scanId: r.scanId,
      scannedAt: r.scannedAt,
      tier: r.tier,
      grade: data.summary?.grade ?? null,
      riskScore: data.summary?.riskScore ?? null,
      // The stored field is totalVulnerabilities (see worker.ts's reportData) —
      // this read `vulnCount`, a name that has never existed on a report, so
      // every history entry ever returned this null regardless of the real count.
      vulnCount: data.summary?.totalVulnerabilities ?? null,
    };
  });

  res.json(history);
});

// ── GET /api/monitor/subscriptions/:id/alerts ────────────────────────────────
// List CVE alerts for a subscription.

router.get("/monitor/subscriptions/:id/alerts", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  // Order by EPSS × severity_weight descending (highest exploit probability × impact first)
  const alerts = await db
    .select()
    .from(cveAlertsTable)
    .where(eq(cveAlertsTable.subscriptionId, subId))
    .orderBy(
      sql`COALESCE(${cveAlertsTable.epssScore}, 0) * CASE ${cveAlertsTable.severity}
        WHEN 'CRITICAL' THEN 4
        WHEN 'HIGH' THEN 3
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 1
        ELSE 1 END DESC`,
      desc(cveAlertsTable.detectedAt),
    );

  res.json(alerts);
});

// ── GET /api/monitor/subscriptions/:id/score-history ──────────────────────────
// Return the last 30 score history points for a subscription (for charting).

router.get("/monitor/subscriptions/:id/score-history", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select({ id: monitorSubscriptionsTable.id })
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  // Join with reports to include reportId so the frontend can link to each report
  const history = await db
    .select({
      id: monitorScoreHistoryTable.id,
      subscriptionId: monitorScoreHistoryTable.subscriptionId,
      scanId: monitorScoreHistoryTable.scanId,
      grade: monitorScoreHistoryTable.grade,
      riskScore: monitorScoreHistoryTable.riskScore,
      criticalCount: monitorScoreHistoryTable.criticalCount,
      highCount: monitorScoreHistoryTable.highCount,
      scannedAt: monitorScoreHistoryTable.scannedAt,
      reportId: reportsTable.id,
    })
    .from(monitorScoreHistoryTable)
    .leftJoin(reportsTable, eq(reportsTable.scanId, monitorScoreHistoryTable.scanId))
    .where(eq(monitorScoreHistoryTable.subscriptionId, subId))
    .orderBy(desc(monitorScoreHistoryTable.scannedAt))
    .limit(30);

  res.json(history.reverse()); // oldest first for charting
});

// ── GET /api/monitor/subscriptions/:id/regressions ───────────────────────────
// Return regressions from the most recent completed monitor scan.

router.get("/monitor/subscriptions/:id/regressions", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select({ id: monitorSubscriptionsTable.id })
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  // Find the most recent scan tracked in score history
  const [latestHistory] = await db
    .select({ scanId: monitorScoreHistoryTable.scanId })
    .from(monitorScoreHistoryTable)
    .where(eq(monitorScoreHistoryTable.subscriptionId, subId))
    .orderBy(desc(monitorScoreHistoryTable.scannedAt))
    .limit(1);

  if (!latestHistory?.scanId) {
    res.json([]);
    return;
  }

  const regressions = await db
    .select()
    .from(monitorRegressionsTable)
    .where(
      and(
        eq(monitorRegressionsTable.subscriptionId, subId),
        eq(monitorRegressionsTable.scanId, latestHistory.scanId),
      ),
    )
    .orderBy(desc(monitorRegressionsTable.detectedAt));

  res.json(regressions);
});

// ── GET /api/monitor/subscriptions/:id/pulses ────────────────────────────────
// The hourly pulse history, newest first. Powers the uptime strip and the
// response-time chart — the part of the dashboard that has something to say on
// the thirteen days between scans.

const MAX_PULSE_HOURS = 30 * 24;

router.get("/monitor/subscriptions/:id/pulses", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const subId = req.params.id;

  const [sub] = await db
    .select({ id: monitorSubscriptionsTable.id })
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  // Clamped rather than rejected: a caller asking for a year gets the thirty
  // days that exist, which is the honest answer, not an error.
  const requested = Number(req.query["hours"]);
  const hours = Number.isFinite(requested) && requested > 0
    ? Math.min(Math.floor(requested), MAX_PULSE_HOURS)
    : 48;

  const pulses = await db
    .select({
      id: monitorPulseChecksTable.id,
      checkedAt: monitorPulseChecksTable.checkedAt,
      reachable: monitorPulseChecksTable.reachable,
      httpStatus: monitorPulseChecksTable.httpStatus,
      responseTimeMs: monitorPulseChecksTable.responseTimeMs,
      certDaysRemaining: monitorPulseChecksTable.certDaysRemaining,
      failureReason: monitorPulseChecksTable.failureReason,
      presentHeaders: monitorPulseChecksTable.presentHeaders,
    })
    .from(monitorPulseChecksTable)
    .where(
      and(
        eq(monitorPulseChecksTable.subscriptionId, subId),
        gte(monitorPulseChecksTable.checkedAt, new Date(Date.now() - hours * 60 * 60 * 1000)),
      ),
    )
    .orderBy(desc(monitorPulseChecksTable.checkedAt));

  const summary = summariseUptime(pulses);

  res.json({ pulses, summary, windowHours: hours });
});

// ── POST /api/monitor/subscriptions/:id/scan ─────────────────────────────────
// Immediately enqueue a manual deep scan for a subscription.

router.post("/monitor/subscriptions/:id/scan", monitorRateLimit, async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  // String(): with a middleware in the handler chain Express widens req.params
  // to string | string[]. A route param cannot actually repeat, so this only
  // restates what the router already guarantees.
  const subId = String(req.params.id);

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(
      and(
        eq(monitorSubscriptionsTable.id, subId),
        eq(monitorSubscriptionsTable.userId, req.user.id),
      ),
    );

  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }

  if (sub.status !== "active") {
    res.status(400).json({ error: "Subscription is not active" });
    return;
  }

  // A plan holder's monitored sites rescan free, any time — the scheduler
  // would rescan them anyway, and this only does it sooner.
  //
  // Everyone else pays for it like any other scan (free scans, then credits).
  // It used to be allowed while free scans remained but charged NOTHING, so a
  // free user could press it up to 20 times a day without ever using one of
  // their free scans.
  //
  // hasLivePlan, not monitorEntitlement: the latter reports "no plan" while
  // MONITORING_REQUIRES_PLAN is off, which would charge a paying subscriber.
  const coveredByPlan = await hasLivePlan(req.user.id);
  let paidWith: PaidWith | null = null;
  if (!coveredByPlan) {
    paidWith = await chargeScan(req.user.id);
    if (paidWith === null) {
      res.status(403).json({ error: TRIAL_LIMIT_MESSAGE, code: TRIAL_LIMIT_CODE });
      return;
    }
  }

  let scanId: string | null = null;
  let baselineScanId: string | null = null;
  try {
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId: req.user.id,
        userEmail: req.user.email ?? "",
        targetUrl: sub.targetUrl,
        tier: "deep",
        status: "paid",
        origin: "monitor",
        paidWith,
      })
      .returning();
    scanId = scan.id;

    await enqueueScan({
      scanId: scan.id,
      userId: req.user.id,
      targetUrl: sub.targetUrl,
      tier: "deep",
      monitorSubscriptionId: sub.id,
    });

    await db
      .update(scansTable)
      .set({ status: "queued", startedAt: new Date() })
      .where(eq(scansTable.id, scan.id));

    logger.info({ subscriptionId: sub.id, scanId: scan.id }, "Manual monitor scan queued");

    res.json({ scanId: scan.id });
  } catch (err) {
    logger.error({ err }, "Failed to enqueue manual monitor scan");
    // Paid for, never ran: give it back. Once the row exists the worker's
    // exactly-once refund path applies; before that, the charge is returned
    // directly.
    try {
      if (scanId) {
        await db.update(scansTable).set({ status: "failed", error: "Could not be queued" }).where(eq(scansTable.id, scanId));
        await refundFailedScan(scanId);
      } else {
        await refundCharge(req.user.id, paidWith);
      }
    } catch (refundErr) {
      logger.error({ err: refundErr }, "Could not refund a manual monitor scan that failed to queue");
    }
    res.status(500).json({ error: "Failed to enqueue scan. You were not charged." });
  }
});

export default router;

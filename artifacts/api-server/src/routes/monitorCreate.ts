import { type IRouter } from "express";
import { fetchLatestReport, CreateMonitorBody, monitorRateLimit, requireMonitorAuth } from "./monitorShared";
import { db, monitorSubscriptionsTable, scansTable } from "@workspace/db";
import { eq, and, count } from "drizzle-orm";
import { enqueueScan } from "../lib/queue";
import { logger } from "../lib/logger";
import { checkScanTarget } from "../lib/ssrfGuard";
import { trialScansExhausted, TRIAL_LIMIT_MESSAGE, TRIAL_LIMIT_CODE } from "../lib/freeTrial";
import { monitorEntitlement } from "../lib/entitlements";
import { hasLivePlan, chargeScan, refundCharge, refundFailedScan, type PaidWith } from "../lib/billing";
import { creditBalance } from "../lib/credits";

/** POST /api/monitor/subscriptions: create a monitoring subscription. */



export function registerMonitorCreate(router: IRouter): void {
  // ── POST /api/monitor/subscriptions ──────────────────────────────────────────
  // Create a new monitoring subscription for a URL.
  // Free unless MONITORING_REQUIRES_PLAN is on; then it needs a Starter or Pro plan (see lib/entitlements.ts).


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
}

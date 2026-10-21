import { type IRouter } from "express";
import { fetchLatestReport, CreateMonitorBody, monitorRateLimit, requireMonitorAuth } from "./monitorShared";
import { db, monitorSubscriptionsTable, scansTable } from "@workspace/db";
import { sameSite } from "../lib/urlKey";
import { eq, and, count, sql } from "drizzle-orm";
import { enqueueScan } from "../lib/queue";
import { logger } from "../lib/logger";
import { checkScanTarget } from "../lib/ssrfGuard";
import { trialScansExhausted, TRIAL_LIMIT_MESSAGE, TRIAL_LIMIT_CODE, insertScanRow } from "../lib/freeTrial";
import { monitorEntitlement } from "../lib/entitlements";
import { hasLivePlan, chargeScan, refundCharge, refundFailedScan, type PaidWith } from "../lib/billing";
import { creditBalance } from "../lib/credits";

/** POST /api/monitor/subscriptions: create a monitoring subscription. */



export function registerMonitorCreate(router: IRouter): void {
  // ── POST /api/monitor/subscriptions ──────────────────────────────────────────
  // Create a new monitoring subscription for a URL.
  // Free unless MONITORING_REQUIRES_PLAN is on; then one site is free and more need a plan (see lib/entitlements.ts).


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

    // Same guard as POST /scans — a subscription schedules recurring scans, so
    // an internal target here is the SSRF hole on a 3-to-14-day timer.
    const targetCheck = await checkScanTarget(targetUrl);
    if (!targetCheck.ok) {
      res.status(400).json({ error: targetCheck.reason ?? "Invalid URL." });
      return;
    }

    const now = new Date();
    const expiresAt = new Date(now);
    expiresAt.setFullYear(expiresAt.getFullYear() + 1);

    // Charged before the transaction below, because chargeScan draws on the pool and
    // holding the per-user lock while it waits for a second connection could starve
    // the pool. Every refusal after this point gives the charge back, so a refused
    // request still costs nothing. The charge itself is atomic, so two concurrent
    // requests cannot both ride on the last scan left.
    let baselinePaidWith: PaidWith | null = null;
    if (!planHolder) {
      baselinePaidWith = await chargeScan(req.user.id);
      if (baselinePaidWith === null) {
        res.status(403).json({ error: TRIAL_LIMIT_MESSAGE, code: TRIAL_LIMIT_CODE });
        return;
      }
    }

    // The plan count, the duplicate check and the insert run as one transaction under a
    // per-user advisory lock. Without it, two parallel creates both count one site fewer
    // than the limit, both see no duplicate, and both insert.
    type Seeded = { reportId: string; scannedAt: Date; grade: unknown } | null;
    type Outcome =
      | { kind: "created"; sub: typeof monitorSubscriptionsTable.$inferSelect; seededFrom: Seeded }
      | { kind: "limit"; activeCount: number }
      | { kind: "duplicate" };

    let outcome: Outcome;
    try {
      outcome = await db.transaction(async (tx): Promise<Outcome> => {
        await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`monitor-create:${req.user.id}`}))`);

        // Counted rather than trusted from the plan: a limit lowered on a downgrade,
        // or a row added by an admin, must both be reflected without a backfill.
        const [{ value: activeCount }] = await tx
          .select({ value: count() })
          .from(monitorSubscriptionsTable)
          .where(
            and(
              eq(monitorSubscriptionsTable.userId, req.user.id),
              eq(monitorSubscriptionsTable.status, "active"),
            ),
          );
        if (Number(activeCount) >= entitlement.urlLimit) {
          return { kind: "limit", activeCount: Number(activeCount) };
        }

        // An existing active subscription for this user+URL.
        const [existing] = await tx
          .select()
          .from(monitorSubscriptionsTable)
          .where(
            and(
              eq(monitorSubscriptionsTable.userId, req.user.id),
              sameSite(monitorSubscriptionsTable.targetUrl, targetUrl),
              eq(monitorSubscriptionsTable.status, "active"),
            ),
          );
        if (existing) return { kind: "duplicate" };

        // Seed from the most recent existing report for this URL so the card
        // immediately shows the last grade/scan date instead of "Never".
        const existingReport = await fetchLatestReport(req.user.id, targetUrl, tx);
        const seedReportId = existingReport?.id ?? null;
        const seedScanAt = existingReport?.scannedAt ?? null;
        // Said back to the caller, so the page can tell the owner that an earlier scan of this site was found and is being shown.
        const seededFrom: Seeded = existingReport
          ? {
              reportId: existingReport.id,
              scannedAt: existingReport.scannedAt,
              grade: (existingReport.data as { summary?: { grade?: unknown } } | null)?.summary?.grade ?? null,
            }
          : null;

        const [created] = await tx
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
        return { kind: "created", sub: created!, seededFrom };
      });
    } catch (err) {
      await refundCharge(req.user.id, baselinePaidWith);
      throw err;
    }

    if (outcome.kind === "limit") {
      await refundCharge(req.user.id, baselinePaidWith);
      const { urlLimit } = entitlement;
      const sites = `${urlLimit} monitored site${urlLimit === 1 ? "" : "s"}`;
      res.status(403).json({
        // A free account is pointed at the paid plans; a paid one at its own limit.
        error:
          entitlement.reason === "free"
            ? `A free account watches ${sites}. Subscribe to watch more, or stop monitoring one to add another.`
            : `Your plan covers ${sites}. Upgrade or stop monitoring one to add another.`,
        code: "monitor_url_limit",
        reason: entitlement.reason,
        urlLimit,
        monitoring: outcome.activeCount,
      });
      return;
    }

    if (outcome.kind === "duplicate") {
      await refundCharge(req.user.id, baselinePaidWith);
      res.status(409).json({ error: "You already have an active monitor subscription for this URL." });
      return;
    }

    const sub = outcome.sub;
    const seededFrom = outcome.seededFrom;

    // Always trigger a baseline deep scan immediately on subscription activation.
    // The card is already seeded with the most recent report above so it shows
    // historical data while the new scan runs.
    let baselineScanId: string | null = null;
    try {
      const scan = await insertScanRow({
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
        });
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
        seededFrom,
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
      res.status(201).json({ subscription: sub, initialScanId: null, seededFrom });
    }
  });
}

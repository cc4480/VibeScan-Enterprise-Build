import { type IRouter } from "express";
import { monitorRateLimit } from "./monitorShared";
import { db, monitorSubscriptionsTable, monitorPulseChecksTable, scansTable } from "@workspace/db";
import { eq, and, gte, desc } from "drizzle-orm";
import { enqueueScan } from "../lib/queue";
import { logger } from "../lib/logger";
import { TRIAL_LIMIT_MESSAGE, TRIAL_LIMIT_CODE, TrialExhaustedError, insertScanRow } from "../lib/freeTrial";
import { monitorEntitlement } from "../lib/entitlements";
import { hasLivePlan, chargeScan, refundCharge, refundFailedScan, type PaidWith } from "../lib/billing";
import { summariseUptime } from "../lib/monitorPulse";

/** Per-subscription pulses and the manual scan trigger. */



export function registerMonitorPulses(router: IRouter): void {
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
    try {
      const scan = await insertScanRow({
          userId: req.user.id,
          userEmail: req.user.email ?? "",
          targetUrl: sub.targetUrl,
          tier: "deep",
          status: "paid",
          origin: "monitor",
          paidWith,
        });
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
      if (err instanceof TrialExhaustedError) {
        res.status(403).json({ error: TRIAL_LIMIT_MESSAGE, code: TRIAL_LIMIT_CODE });
        return;
      }
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
}

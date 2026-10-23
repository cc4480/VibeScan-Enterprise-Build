/** The sweep: which subscriptions are due, and queueing their scans. */
import { db, monitorSubscriptionsTable, scansTable } from "@workspace/db";
import { eq, and, isNull } from "drizzle-orm";
import { enqueueScan } from "./queue";
import { logger } from "./logger";
import { sendMonitorScanQueuedEmail } from "./mailer";
import { fireWebhook } from "./webhook";
import { APP_ORIGIN } from "./appOrigin";
import { monitorEntitlement, monitorExpiryApplies } from "./entitlements";

export const SWEEP_QUEUE      = "monitor-sweep";

// ─── Cadence helpers ──────────────────────────────────────────────────────────

/**
 * Days until the next full rescan, from the grade. `opts.minDays` is a floor, an object and not a bare number so `.map(nextScanDelayDays)` cannot pass an array index as one: a free
 * account's site is never rescanned more often than weekly (FREE_MONITOR_MIN_DAYS),
 * so a D or F grade, which would otherwise rescan every 3 days, waits 7. A paid
 * plan passes no floor and keeps the grade-based cadence.
 */
export function nextScanDelayDays(grade: string, opts: { minDays?: number; intervalDays?: number | null } = {}): number {
  // An owner-chosen interval replaces the grade cadence, but only after a real graded scan: an
  // intercepted scan (grade N/A) is retried at the short cadence whatever was chosen.
  const graded = /^[A-F]$/.test(grade);
  const days = opts.intervalDays && graded ? opts.intervalDays : grade === "A" ? 14 : grade === "B" || grade === "C" ? 7 : 3; // D or F: 3
  return Math.max(days, opts.minDays ?? 0);
}

export function computeNextScanAt(grade: string, from: Date = new Date(), opts: { minDays?: number; intervalDays?: number | null } = {}): Date {
  const days = nextScanDelayDays(grade, opts);
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
  /** Off once plans are enforced: the plan, not expiresAt, ends monitoring then. */
  expiryApplies: boolean = monitorExpiryApplies(),
): boolean {
  if (expiryApplies && sub.expiresAt <= now) return false;
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

export type ActiveSub = typeof monitorSubscriptionsTable.$inferSelect;

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
export async function activeEntitledSubscriptions(
  now: Date,
): Promise<{ subs: ActiveSub[]; total: number; skippedUnentitled: number }> {
  const all = await db
    .select()
    .from(monitorSubscriptionsTable)
    // A paused monitor is skipped by every job, so it neither scans nor alerts.
    .where(and(eq(monitorSubscriptionsTable.status, "active"), isNull(monitorSubscriptionsTable.pausedAt)));

  // With plans enforced, the entitlement check below is what ends monitoring.
  const unexpired = monitorExpiryApplies() ? all.filter((sub) => sub.expiresAt > now) : all;

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

// ─── Helper: enqueue a monitor scan ──────────────────────────────────────────

export async function enqueueMonitorScan(sub: {
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

export async function runSweep(): Promise<void> {
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

/**
 * Owner controls on a monitored site that are not "add" or "cancel".
 *
 * PATCH /api/monitor/subscriptions/:id/pause  { paused: boolean }
 *
 * A paused monitor is skipped by every scheduled job (see activeEntitledSubscriptions in
 * monitorScheduler.ts), so it sends no scans, pulse checks, CVE alerts or emails. Nothing
 * is deleted: the history stays readable, and resuming picks up where it left off. It is
 * the honest alternative to cancelling for someone who is redesigning a site or is on
 * holiday and does not want to be alerted about it.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { and, eq } from "drizzle-orm";
import { db, monitorSubscriptionsTable } from "@workspace/db";
import { enforcementEnabled, rescanFloorDays } from "../lib/entitlements";
import { hasLivePlan } from "../lib/billing";
import { mayActFor } from "../lib/team";

const router: IRouter = Router();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const body = z.object({ paused: z.boolean() });

router.patch("/monitor/subscriptions/:id/pause", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const parsed = body.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Send {\"paused\": true} or {\"paused\": false}." });
    return;
  }

  // The owner, or an editor on the owner's team (lib/team.ts); anyone else gets the answer for a site that does not exist.
  const [found] = UUID.test(String(req.params.id))
    ? await db.select().from(monitorSubscriptionsTable).where(eq(monitorSubscriptionsTable.id, String(req.params.id)))
    : [];
  const sub = found && (await mayActFor(req.user.id, found.userId)) ? found : undefined;
  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }
  if (sub.status !== "active") {
    res.status(409).json({ error: "Only an active monitor can be paused or resumed." });
    return;
  }

  // Idempotent: pausing a paused monitor keeps its original pause time.
  const pausedAt = parsed.data.paused ? (sub.pausedAt ?? new Date()) : null;
  await db.update(monitorSubscriptionsTable).set({ pausedAt }).where(eq(monitorSubscriptionsTable.id, sub.id));

  res.json({ id: sub.id, paused: pausedAt !== null, pausedAt });
});

/** The days between full rescans an owner may pick. 3 is today's tightest cadence (a D or F), so no choice scans more often than the product already does. */
export const SCAN_INTERVAL_CHOICES = [3, 7, 14, 30] as const;
const intervalBody = z.object({ days: z.union([z.literal(3), z.literal(7), z.literal(14), z.literal(30), z.null()]) });

router.patch("/monitor/subscriptions/:id/interval", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const parsed = intervalBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: `Send {"days": ${SCAN_INTERVAL_CHOICES.join(", ")}} or {"days": null} for the default.` });
    return;
  }

  const [sub] = await db
    .select()
    .from(monitorSubscriptionsTable)
    .where(and(eq(monitorSubscriptionsTable.id, String(req.params.id)), eq(monitorSubscriptionsTable.userId, req.user.id)));
  if (!sub) {
    res.status(404).json({ error: "Subscription not found" });
    return;
  }
  if (sub.status !== "active") {
    res.status(409).json({ error: "Only an active monitor can change how often it is scanned." });
    return;
  }

  // Re-time the next scan from the last one, so the change takes effect now and not after the old
  // wait runs out. A time already past just makes the monitor due on the next sweep.
  // A free account stays held to the weekly floor, as in the worker (workerMonitor.ts).
  const days = parsed.data.days;
  const update: { scanIntervalDays: number | null; nextScanAt?: Date } = { scanIntervalDays: days };
  if (days && sub.lastScanAt) {
    let floorDays = 0;
    if (enforcementEnabled()) floorDays = rescanFloorDays({ enforced: true, hasLivePlan: await hasLivePlan(req.user.id) });
    update.nextScanAt = new Date(sub.lastScanAt.getTime() + Math.max(days, floorDays) * 24 * 60 * 60 * 1000);
  }
  await db.update(monitorSubscriptionsTable).set(update).where(eq(monitorSubscriptionsTable.id, sub.id));

  res.json({ id: sub.id, scanIntervalDays: days });
});

export default router;

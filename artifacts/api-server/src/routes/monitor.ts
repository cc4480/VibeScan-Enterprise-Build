import { Router, type IRouter } from "express";
import { db, monitorSubscriptionsTable, cveAlertsTable, reportsTable } from "@workspace/db";
import { eq, and, desc } from "drizzle-orm";
import { z } from "zod";
import { enqueueScan } from "../lib/queue";
import { scansTable } from "@workspace/db";
import { logger } from "../lib/logger";

const router: IRouter = Router();

const CreateMonitorBody = z.object({
  targetUrl: z.string().url("Must be a valid URL"),
});

// ── POST /api/monitor/subscriptions ──────────────────────────────────────────
// Create a new monitoring subscription for a URL.
// With DISABLE_PAYMENTS=true this is granted immediately.

router.post("/monitor/subscriptions", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CreateMonitorBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Invalid request" });
    return;
  }

  const { targetUrl } = parsed.data;
  const paymentsDisabled = process.env.DISABLE_PAYMENTS === "true";

  if (!paymentsDisabled) {
    res.status(503).json({ error: "Subscription payments are not yet configured." });
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

  const [sub] = await db
    .insert(monitorSubscriptionsTable)
    .values({
      userId: req.user.id,
      userEmail: req.user.email ?? "",
      targetUrl,
      status: "active",
      expiresAt,
    })
    .returning();

  // Immediately trigger an initial deep scan so the user has a baseline
  try {
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId: req.user.id,
        userEmail: req.user.email ?? "",
        targetUrl,
        tier: "deep",
        status: "paid",
      })
      .returning();

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

  // Attach latest report info to each subscription
  const enriched = await Promise.all(
    subs.map(async (sub) => {
      let lastReport: { id: string; grade: string | null; riskScore: number | null } | null = null;

      if (sub.lastReportId) {
        const [report] = await db
          .select({ id: reportsTable.id, data: reportsTable.data })
          .from(reportsTable)
          .where(eq(reportsTable.id, sub.lastReportId));

        if (report) {
          const data = report.data as { summary?: { grade?: string; riskScore?: number } };
          lastReport = {
            id: report.id,
            grade: data.summary?.grade ?? null,
            riskScore: data.summary?.riskScore ?? null,
          };
        }
      }

      // Count pending alerts
      const alerts = await db
        .select()
        .from(cveAlertsTable)
        .where(eq(cveAlertsTable.subscriptionId, sub.id));

      return {
        ...sub,
        lastReport,
        alertCount: alerts.length,
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

  const alerts = await db
    .select()
    .from(cveAlertsTable)
    .where(eq(cveAlertsTable.subscriptionId, subId))
    .orderBy(desc(cveAlertsTable.detectedAt));

  res.json(alerts);
});

export default router;

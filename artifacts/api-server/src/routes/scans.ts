import { Router, type IRouter } from "express";
import { db, scansTable, reportsTable } from "@workspace/db";
import { eq, and, desc, inArray } from "drizzle-orm";
import {
  CreateScanBody,
  ListScansResponseItem,
  GetScanStatusResponse,
} from "@workspace/api-zod";
import { enqueueScan } from "../lib/queue";

const router: IRouter = Router();

const STATUS_PROGRESS: Record<string, number> = {
  pending: 0,
  paid: 10,
  queued: 20,
  scanning: 55,
  analyzing: 80,
  complete: 100,
  failed: 0,
};

router.get("/scans", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const scans = await db
      .select()
      .from(scansTable)
      .where(eq(scansTable.userId, req.user.id))
      .orderBy(desc(scansTable.createdAt));

    // Single batched query for all report IDs — no N+1
    const completedIds = scans
      .filter((s) => s.status === "complete")
      .map((s) => s.id);

    const reports =
      completedIds.length > 0
        ? await db
            .select({ id: reportsTable.id, scanId: reportsTable.scanId })
            .from(reportsTable)
            .where(inArray(reportsTable.scanId, completedIds))
        : [];

    const reportByScanId = new Map(reports.map((r) => [r.scanId, r.id]));

    res.json(
      scans.map((s) =>
        ListScansResponseItem.parse({
          id: s.id,
          userId: s.userId,
          userEmail: s.userEmail,
          targetUrl: s.targetUrl,
          tier: s.tier,
          status: s.status,
          stripeSessionId: s.stripeSessionId ?? null,
          stripePaymentIntentId: s.stripePaymentIntentId ?? null,
          createdAt: s.createdAt,
          startedAt: s.startedAt ?? null,
          completedAt: s.completedAt ?? null,
          error: s.error ?? null,
          reportId: reportByScanId.get(s.id) ?? null,
        }),
      ),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to list scans");
    res.status(500).json({ error: "Failed to list scans" });
  }
});

router.post("/scans", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Invalid request" });
    return;
  }

  const { targetUrl, tier } = parsed.data;

  // Reject credit pack tiers — app is free, no credit system
  if (tier === "pack_5" || tier === "pack_20") {
    res.status(400).json({ error: "Credit packs are not available" });
    return;
  }

  try {
    new URL(targetUrl);
  } catch {
    res.status(400).json({ error: "Invalid URL. Must start with http:// or https://" });
    return;
  }

  const parsedUrl = new URL(targetUrl);
  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    res.status(400).json({ error: "Invalid URL. Must start with http:// or https://" });
    return;
  }

  try {
    const [scan] = await db
      .insert(scansTable)
      .values({
        userId: req.user.id,
        userEmail: req.user.email ?? "",
        targetUrl,
        tier,
        status: "queued",
        startedAt: new Date(),
      })
      .returning();

    await enqueueScan({ scanId: scan.id, userId: req.user.id, targetUrl, tier });

    res.status(201).json({ scanId: scan.id, checkoutUrl: null, creditUsed: false });
  } catch (err) {
    req.log.error({ err }, "Failed to create scan");
    res.status(500).json({ error: "Failed to create scan. Please try again." });
  }
});

router.get("/scans/:id/status", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  try {
    const [scan] = await db
      .select()
      .from(scansTable)
      .where(and(eq(scansTable.id, rawId), eq(scansTable.userId, req.user.id)));

    if (!scan) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }

    let reportId: string | null = null;
    let grade: string | null = null;
    if (scan.status === "complete") {
      const [report] = await db
        .select({ id: reportsTable.id, data: reportsTable.data })
        .from(reportsTable)
        .where(eq(reportsTable.scanId, scan.id));
      reportId = report?.id ?? null;
      const reportData = report?.data as { summary?: { grade?: string } } | undefined;
      grade = reportData?.summary?.grade ?? null;
    }

    res.json(
      GetScanStatusResponse.parse({
        id: scan.id,
        targetUrl: scan.targetUrl,
        tier: scan.tier,
        status: scan.status,
        progress: STATUS_PROGRESS[scan.status] ?? 0,
        createdAt: scan.createdAt,
        startedAt: scan.startedAt ?? null,
        completedAt: scan.completedAt ?? null,
        error: scan.error ?? null,
        reportId,
        grade,
      }),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to fetch scan status");
    res.status(500).json({ error: "Failed to fetch scan status" });
  }
});

export default router;

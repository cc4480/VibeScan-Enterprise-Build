import { Router, type IRouter } from "express";
import { db, scansTable, reportsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import {
  CreateScanBody,
  ListScansResponseItem,
  GetScanStatusResponse,
} from "@workspace/api-zod";

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

  const scans = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.userId, req.user.id))
    .orderBy(scansTable.createdAt);

  const scansWithReports = await Promise.all(
    scans.map(async (scan) => {
      if (scan.status !== "complete") {
        return { ...scan, reportId: null };
      }
      const [report] = await db
        .select({ id: reportsTable.id })
        .from(reportsTable)
        .where(eq(reportsTable.scanId, scan.id));
      return { ...scan, reportId: report?.id ?? null };
    }),
  );

  res.json(
    scansWithReports.map((s) =>
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
        reportId: s.reportId ?? null,
      }),
    ),
  );
});

router.post("/scans", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { targetUrl, tier } = parsed.data;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      throw new Error("bad protocol");
    }
  } catch {
    res.status(400).json({ error: "Invalid URL format. Must be http:// or https://" });
    return;
  }

  const [scan] = await db
    .insert(scansTable)
    .values({
      userId: req.user.id,
      userEmail: req.user.email ?? "",
      targetUrl,
      tier,
      status: "pending",
    })
    .returning();

  res.status(201).json({
    scanId: scan.id,
    checkoutUrl: null,
    creditUsed: false,
  });
});

router.get("/scans/:id/status", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  const [scan] = await db
    .select()
    .from(scansTable)
    .where(and(eq(scansTable.id, rawId), eq(scansTable.userId, req.user.id)));

  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  let reportId: string | null = null;
  if (scan.status === "complete") {
    const [report] = await db
      .select({ id: reportsTable.id })
      .from(reportsTable)
      .where(eq(reportsTable.scanId, scan.id));
    reportId = report?.id ?? null;
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
    }),
  );
});

export default router;

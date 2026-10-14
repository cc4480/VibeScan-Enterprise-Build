import { Router, type IRouter } from "express";
import { UUID_ANY } from "./accountShared";
import { db, scansTable, reportsTable } from "@workspace/db";
import { eq, and, desc, inArray, ne } from "drizzle-orm";
import { ListScansResponseItem, GetScanStatusResponse } from "@workspace/api-zod";
import { scanRateLimit, scanNetworkRateLimit, requireScanAuth } from "./scansGuards";
import { createScanHandler } from "./scansCreate";
export { scanRateLimit, scanNetworkRateLimit } from "./scansGuards";
export { createScanHandler } from "./scansCreate";

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

/** Rows returned by GET /scans: 200 unless asked for fewer or more, never above 500. */
function listLimit(raw: unknown): number {
  const n = Number.parseInt(String(raw ?? ""), 10);
  return Number.isFinite(n) ? Math.min(Math.max(n, 1), 500) : 200;
}

router.get("/scans", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const scans = await db
      .select()
      .from(scansTable)
      // Re-checks of a single finding (origin "verify") are not scans the person asked for; they appear on the finding.
      .where(and(eq(scansTable.userId, req.user.id), ne(scansTable.origin, "verify")))
      .orderBy(desc(scansTable.createdAt))
      // Newest first and bounded: an account that scans on a schedule for a year would otherwise
      // download every row on each page load. ?limit= up to 500.
      .limit(listLimit(req.query["limit"]));

    // Batch-fetch reports for all complete scans to avoid N+1
    const completeScanIds = scans
      .filter((s) => s.status === "complete")
      .map((s) => s.id);

    const reports =
      completeScanIds.length > 0
        ? await db
            .select({ id: reportsTable.id, scanId: reportsTable.scanId })
            .from(reportsTable)
            .where(inArray(reportsTable.scanId, completeScanIds))
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
          reportId: s.status === "complete" ? (reportByScanId.get(s.id) ?? null) : null,
        }),
      ),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to list scans");
    res.status(500).json({ error: "Failed to list scans" });
  }
});

router.post("/scans", requireScanAuth, scanRateLimit, scanNetworkRateLimit, createScanHandler);

router.get("/scans/:id/status", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  if (!rawId || !UUID_ANY.test(rawId)) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

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
});

export default router;
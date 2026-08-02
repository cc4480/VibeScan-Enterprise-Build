import { Router, type IRouter } from "express";
import { db, reportsTable } from "@workspace/db";
import { and, eq } from "drizzle-orm";
import { GetReportResponse } from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/reports/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  try {
    const [report] = await db
      .select()
      .from(reportsTable)
      .where(and(eq(reportsTable.id, id), eq(reportsTable.userId, req.user.id)));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }

    res.json(
      GetReportResponse.parse({
        id: report.id,
        scanId: report.scanId,
        userId: report.userId,
        targetUrl: report.targetUrl,
        tier: report.tier,
        scannedAt: report.scannedAt,
        duration: report.duration ?? null,
        createdAt: report.createdAt,
        data: report.data,
      }),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to fetch report");
    res.status(500).json({ error: "Failed to fetch report" });
  }
});

export default router;

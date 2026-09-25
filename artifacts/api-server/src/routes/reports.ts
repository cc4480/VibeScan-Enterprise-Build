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

    const parsed = GetReportResponse.parse({
      id: report.id,
      scanId: report.scanId,
      userId: report.userId,
      targetUrl: report.targetUrl,
      tier: report.tier,
      scannedAt: report.scannedAt,
      duration: report.duration ?? null,
      createdAt: report.createdAt,
      data: report.data,
    });

    // The schema is strict and does not list these two, so parse() drops them:
    // the owner's own report then said "not recorded, run before test records
    // were kept" and the OWASP card said "no record" for every row, on scans that
    // had recorded a full ledger. The share page and the MCP read the stored data
    // directly and were never affected. Carried through from the stored row.
    const stored = report.data as { tests?: unknown; compliance?: unknown };
    res.json({
      ...parsed,
      data: {
        ...parsed.data,
        ...(stored.tests !== undefined ? { tests: stored.tests } : {}),
        ...(stored.compliance !== undefined ? { compliance: stored.compliance } : {}),
      },
    });
  } catch (err) {
    req.log.error({ err }, "Failed to fetch report");
    res.status(500).json({ error: "Failed to fetch report" });
  }
});

export default router;

import { Router, type IRouter } from "express";
import { db, reportsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { GetReportResponse } from "@workspace/api-zod";
import { UUID_ANY } from "./accountShared";
import { changesForReport } from "../lib/scanDiffLoader";
import { withNoteFreeTotals } from "../lib/reportTotals";
import { teamRoleOf } from "../lib/team";
import { getBranding } from "../lib/branding";

const router: IRouter = Router();

router.get("/reports/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  if (!id || !UUID_ANY.test(id)) {
    res.status(404).json({ error: "Report not found" });
    return;
  }

  try {
    const [report] = await db
      .select()
      .from(reportsTable)
      .where(eq(reportsTable.id, id));

    // The owner reads it; so does a teammate the owner invited (lib/team.ts). Anyone else gets the same answer as for a
    // report that does not exist.
    const isOwner = report?.userId === req.user.id;
    const teamRole = report !== undefined && !isOwner ? await teamRoleOf(req.user.id, report.userId) : null;
    const asTeammate = teamRole !== null;
    if (!report || (!isOwner && !asTeammate)) {
      res.status(404).json({ error: "Report not found" });
      return;
    }

    const parsed = GetReportResponse.parse({
      id: report.id,
      scanId: report.scanId,
      // A teammate is not told the owner's account id: for some legacy accounts that id has been a credential.
      userId: isOwner ? report.userId : req.user.id,
      targetUrl: report.targetUrl,
      tier: report.tier,
      scannedAt: report.scannedAt,
      duration: report.duration ?? null,
      createdAt: report.createdAt,
      // Totals saved before the notes left them are recounted here (lib/reportTotals.ts).
      data: withNoteFreeTotals(report.data),
    });

    // The schema is strict and does not list these two, so parse() drops them:
    // the owner's own report then said "not recorded, run before test records
    // were kept" and the OWASP card said "no record" for every row, on scans that
    // had recorded a full ledger. The share page and the MCP read the stored data
    // directly and were never affected. Carried through from the stored row.
    const stored = report.data as { tests?: unknown; compliance?: unknown; withheld?: unknown; interception?: unknown };
    // What changed since the last scan of this site (lib/scanDiff.ts). A failure here must never
    // cost someone their report, so it degrades to "no comparison".
    const changes = await changesForReport(report.userId, { scanId: report.scanId, targetUrl: report.targetUrl, scannedAt: report.scannedAt, data: report.data }).catch((err) => {
      req.log.warn({ err }, "Could not compare with the previous scan");
      return null;
    });
    res.json({
      ...parsed,
      // Which of the two the caller is, so the page can show a teammate the read-only view.
      access: isOwner ? "owner" : "team",
      // What a teammate may do: an editor can also file tickets from the report; a viewer only reads.
      ...(isOwner ? {} : { role: teamRole }),
      // Whose name the PDF carries: the report owner's, for a teammate too.
      brand: await getBranding(report.userId),
      data: {
        ...parsed.data,
        ...(stored.tests !== undefined ? { tests: stored.tests } : {}),
        ...(stored.compliance !== undefined ? { compliance: stored.compliance } : {}),
        // Same reason: what the scan withheld and why, and what answered instead of the app.
        ...(stored.withheld !== undefined ? { withheld: stored.withheld } : {}),
        ...(stored.interception !== undefined ? { interception: stored.interception } : {}),
        ...(changes ? { changes } : {}),
      },
    });
  } catch (err) {
    req.log.error({ err }, "Failed to fetch report");
    res.status(500).json({ error: "Failed to fetch report" });
  }
});

export default router;

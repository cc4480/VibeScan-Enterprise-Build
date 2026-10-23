/**
 * The evidence pack for a report, and the check that SecScan issued one.
 *
 * Downloading is for the report's owner and the teammates they invited. Verifying is public on purpose: the person who is handed a pack is usually
 * not a SecScan user, and the answer reveals nothing but whether a manifest hash was signed by SecScan.
 * What a pack holds and what its signature means are in lib/evidencePack.ts and lib/evidenceSign.ts.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { db, reportsTable } from "@workspace/db";
import { buildEvidencePack } from "../lib/evidencePack";
import { verifyManifestSignature } from "../lib/evidenceSign";
import { rateLimitMiddleware } from "../lib/rateLimit";
import { isTeamViewer } from "../lib/team";
import { APP_ORIGIN } from "../lib/appOrigin";
import { UUID } from "./appRouteRunner";

const router: IRouter = Router();

const packLimit = rateLimitMiddleware({ rules: [{ windowMs: 60_000, max: 20, label: "minute" }], name: "evidence-pack" });
const verifyLimit = rateLimitMiddleware({ rules: [{ windowMs: 60_000, max: 60, label: "minute" }], name: "evidence-verify" });

/** The organisation name a pack is prepared for: one line of plain text, or nothing. */
const preparedFor = (raw: unknown): string | null => {
  const text = typeof raw === "string" ? raw.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 120) : "";
  return text || null;
};

router.get("/reports/:id/evidence-pack", packLimit, async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Sign in to download an evidence pack." }); return; }
  const reportId = String(req.params["id"]);
  if (!UUID.test(reportId)) { res.status(404).json({ error: "Report not found" }); return; }
  const [report] = await db
    .select({ id: reportsTable.id, userId: reportsTable.userId, targetUrl: reportsTable.targetUrl, scannedAt: reportsTable.scannedAt, tier: reportsTable.tier, data: reportsTable.data })
    .from(reportsTable)
    .where(eq(reportsTable.id, reportId));
  // The owner, or a teammate the owner invited (lib/team.ts); anyone else is told the report does not exist.
  if (!report || (report.userId !== req.user.id && !(await isTeamViewer(req.user.id, report.userId)))) {
    res.status(404).json({ error: "Report not found" });
    return;
  }

  const pack = buildEvidencePack({
    reportId: report.id, targetUrl: report.targetUrl, scannedAt: report.scannedAt, tier: report.tier, data: report.data,
    preparedFor: preparedFor(req.query["for"]), origin: APP_ORIGIN,
  });
  req.log.info({ reportId, bytes: pack.bytes.length, signed: pack.signed }, "Evidence pack downloaded");
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", `attachment; filename="${pack.filename}"`);
  res.setHeader("Content-Length", String(pack.bytes.length));
  res.setHeader("X-Manifest-SHA256", pack.manifestSha256);
  res.setHeader("Cache-Control", "no-store");
  res.end(pack.bytes);
});

const VerifyBody = z.object({ manifestSha256: z.string().max(64), signature: z.string().max(64) });

router.post("/evidence/verify", verifyLimit, (req, res): void => {
  const parsed = VerifyBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: "Send manifestSha256 and signature, both from the pack's SIGNATURE.json." }); return; }
  res.setHeader("Cache-Control", "no-store");
  res.json({ valid: verifyManifestSignature(parsed.data.manifestSha256.toLowerCase(), parsed.data.signature.toLowerCase()) });
});

export default router;

/**
 * "I fixed this": start a re-check of one finding, and read where each one stands.
 * The rules (what counts as fixed, the limits, why it is free) are in lib/verifyFix.ts.
 * Signed-in accounts only, and only for findings in the caller's own reports.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { latestVerifications, startVerification } from "../lib/verifyFix";
import { UUID } from "./appRouteRunner";

const router: IRouter = Router();

const Body = z.object({ findingId: z.string().min(1).max(100) });

router.post("/reports/:id/verify", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Sign in to check a fix." });
    return;
  }
  const reportId = String(req.params["id"]);
  const parsed = Body.safeParse(req.body);
  if (!UUID.test(reportId) || !parsed.success) {
    res.status(404).json({ error: "That finding was not found in your report." });
    return;
  }
  const result = await startVerification({ userId: req.user.id, userEmail: req.user.email ?? "", reportId, findingId: parsed.data.findingId });
  if (!result.ok) {
    res.status(result.status).json({ error: result.message, code: result.code });
    return;
  }
  req.log.info({ reportId, verificationId: result.verificationId }, "Fix verification started");
  res.status(202).json({ verificationId: result.verificationId, scanId: result.scanId });
});

router.get("/reports/:id/verifications", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const reportId = String(req.params["id"]);
  if (!UUID.test(reportId)) {
    res.json({ verifications: [] });
    return;
  }
  res.setHeader("Cache-Control", "no-store");
  res.json({ verifications: await latestVerifications(req.user.id, reportId) });
});

export default router;

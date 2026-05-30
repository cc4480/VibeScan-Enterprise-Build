import { Router, type IRouter } from "express";
import { db, dismissedFindingsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { z } from "zod";
import { findingFingerprint, canonicalizeTargetUrl } from "../lib/fingerprint";

const router: IRouter = Router();

const DismissBody = z.object({
  targetUrl: z.string().min(1),
  findingName: z.string().min(1),
  findingCategory: z.string().min(1),
  findingEvidence: z.string().optional(),
  reason: z.string().optional(),
});

router.get("/dismissals", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const rawTargetUrl = typeof req.query.targetUrl === "string" ? req.query.targetUrl : null;
  if (!rawTargetUrl) {
    res.status(400).json({ error: "targetUrl query parameter is required" });
    return;
  }
  const targetUrl = canonicalizeTargetUrl(rawTargetUrl);

  try {
    const items = await db
      .select()
      .from(dismissedFindingsTable)
      .where(
        and(
          eq(dismissedFindingsTable.userId, req.user.id),
          eq(dismissedFindingsTable.targetUrl, targetUrl),
        ),
      );

    res.json(
      items.map((d) => ({
        fingerprint: d.findingFingerprint,
        findingName: d.findingName,
        findingCategory: d.findingCategory,
      })),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to fetch dismissals");
    res.status(500).json({ error: "Failed to fetch dismissals" });
  }
});

router.post("/dismissals", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = DismissBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { targetUrl: rawTargetUrlPost, findingName, findingCategory, findingEvidence, reason } = parsed.data;
  const targetUrl = canonicalizeTargetUrl(rawTargetUrlPost);
  const fingerprint = findingFingerprint(findingCategory, findingName, findingEvidence);

  try {
    await db
      .insert(dismissedFindingsTable)
      .values({
        userId: req.user.id,
        targetUrl,
        findingFingerprint: fingerprint,
        findingName,
        findingCategory,
        reason: reason ?? "false_positive",
      })
      .onConflictDoNothing();

    res.status(201).json({ fingerprint });
  } catch (err) {
    req.log.error({ err }, "Failed to create dismissal");
    res.status(500).json({ error: "Failed to create dismissal" });
  }
});

router.delete("/dismissals/:fingerprint", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const { fingerprint } = req.params;
  const rawTargetUrlDelete = typeof req.query.targetUrl === "string" ? req.query.targetUrl : null;
  if (!rawTargetUrlDelete) {
    res.status(400).json({ error: "targetUrl query parameter is required" });
    return;
  }
  const targetUrl = canonicalizeTargetUrl(rawTargetUrlDelete);

  try {
    await db
      .delete(dismissedFindingsTable)
      .where(
        and(
          eq(dismissedFindingsTable.userId, req.user.id),
          eq(dismissedFindingsTable.targetUrl, targetUrl),
          eq(dismissedFindingsTable.findingFingerprint, fingerprint),
        ),
      );

    res.status(204).send();
  } catch (err) {
    req.log.error({ err }, "Failed to delete dismissal");
    res.status(500).json({ error: "Failed to delete dismissal" });
  }
});

export default router;

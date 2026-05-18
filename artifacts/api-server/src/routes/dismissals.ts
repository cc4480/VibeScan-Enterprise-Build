import { Router, type IRouter } from "express";
import { db, dismissedFindingsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { createHash } from "node:crypto";
import { z } from "zod";

const router: IRouter = Router();

function fingerprintFinding(category: string, name: string): string {
  return createHash("sha256")
    .update(`${category}::${name.toLowerCase().trim()}`)
    .digest("hex")
    .slice(0, 20);
}

const DismissBody = z.object({
  targetUrl: z.string().min(1),
  findingName: z.string().min(1),
  findingCategory: z.string().min(1),
});

router.get("/dismissals", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const targetUrl = typeof req.query.targetUrl === "string" ? req.query.targetUrl : null;
  if (!targetUrl) {
    res.status(400).json({ error: "targetUrl query parameter is required" });
    return;
  }

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

  const { targetUrl, findingName, findingCategory } = parsed.data;
  const fingerprint = fingerprintFinding(findingCategory, findingName);

  try {
    await db
      .insert(dismissedFindingsTable)
      .values({
        userId: req.user.id,
        targetUrl,
        findingFingerprint: fingerprint,
        findingName,
        findingCategory,
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
  const targetUrl = typeof req.query.targetUrl === "string" ? req.query.targetUrl : null;
  if (!targetUrl) {
    res.status(400).json({ error: "targetUrl query parameter is required" });
    return;
  }

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

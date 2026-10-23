import { Router, type IRouter } from "express";
import { db, dismissedFindingsTable } from "@workspace/db";
import { eq, and, count, sql } from "drizzle-orm";
import { z } from "zod";
import { findingFingerprint, canonicalizeTargetUrl } from "../lib/fingerprint";
import { zodMessage } from "../lib/zodMessage";
import { rateLimitMiddleware } from "../lib/rateLimit";

const router: IRouter = Router();

/**
 * Upper bounds on what a dismissal may carry. The URL is also indexed (btree), which cannot
 * hold a very long value; the rest are display text and a short reason code. A finding's
 * evidence is the longest of these: it is what the fingerprint is built from.
 */
export const DISMISSAL_LIMITS = {
  targetUrl: 2048,
  findingName: 200,
  findingCategory: 200,
  findingEvidence: 2000,
  reason: 500,
} as const;

/** Dismissals one account may hold. Re-dismissing one already held does not count again. */
export const DISMISSAL_CAP_PER_USER = 2000;

/** Cap on creating dismissals from one address. Generous: dismissing is a click per finding. */
const dismissalWriteLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60_000, max: 120, label: "minute" }],
  name: "dismissals",
});

const DismissBody = z.object({
  targetUrl: z.string().min(1).max(DISMISSAL_LIMITS.targetUrl, "Target URL is too long"),
  findingName: z.string().min(1).max(DISMISSAL_LIMITS.findingName, "Finding name is too long"),
  findingCategory: z.string().min(1).max(DISMISSAL_LIMITS.findingCategory, "Finding category is too long"),
  findingEvidence: z.string().max(DISMISSAL_LIMITS.findingEvidence, "Finding evidence is too long").optional(),
  reason: z.string().max(DISMISSAL_LIMITS.reason, "Reason is too long").optional(),
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

router.post("/dismissals", dismissalWriteLimit, async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const parsed = DismissBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: zodMessage(parsed.error) });
    return;
  }

  const { targetUrl: rawTargetUrlPost, findingName, findingCategory, findingEvidence, reason } = parsed.data;
  const targetUrl = canonicalizeTargetUrl(rawTargetUrlPost);
  const fingerprint = findingFingerprint(findingCategory, findingName, findingEvidence);
  const userId = req.user.id;

  try {
    // Count and insert under a per-user advisory lock, so parallel requests cannot all
    // read the same count and push the account past the cap.
    const outcome = await db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`dismissal:${userId}`}))`);

      const [already] = await tx
        .select({ id: dismissedFindingsTable.id })
        .from(dismissedFindingsTable)
        .where(
          and(
            eq(dismissedFindingsTable.userId, userId),
            eq(dismissedFindingsTable.targetUrl, targetUrl),
            eq(dismissedFindingsTable.findingFingerprint, fingerprint),
          ),
        )
        .limit(1);
      if (already) return "ok" as const;

      const [{ value: held }] = await tx
        .select({ value: count() })
        .from(dismissedFindingsTable)
        .where(eq(dismissedFindingsTable.userId, userId));
      if (Number(held) >= DISMISSAL_CAP_PER_USER) return "full" as const;

      await tx
        .insert(dismissedFindingsTable)
        .values({
          userId,
          targetUrl,
          findingFingerprint: fingerprint,
          findingName,
          findingCategory,
          reason: reason ?? "false_positive",
        })
        .onConflictDoNothing();
      return "ok" as const;
    });

    if (outcome === "full") {
      res.status(409).json({
        error:
          `This account already holds ${DISMISSAL_CAP_PER_USER} dismissed findings, the most it can keep. ` +
          "Remove some before dismissing more.",
        code: "dismissal_limit",
      });
      return;
    }

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

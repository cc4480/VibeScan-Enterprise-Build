/**
 * The account's privacy choice about the written analysis.
 *
 * GET / PUT /api/account/privacy  { aiAnalysis: boolean }
 *
 * The plain-English analysis of a scan is written by a third-party language model, which
 * is sent the findings (names, descriptions and evidence, scrubbed of anything shaped like
 * a credential) and never the credentials used for a scan. Someone who does not want that
 * can turn it off: scans run exactly as before, every finding is reported, and only the
 * written commentary is left out.
 *
 * Stored as an opt-OUT and presented as an opt-IN, like the email preferences: the default
 * for a column added later must be the behaviour people already have.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { db, usersTable } from "@workspace/db";

const router: IRouter = Router();
const body = z.object({ aiAnalysis: z.boolean() });

router.get("/account/privacy", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const [row] = await db.select({ off: usersTable.aiAnalysisOptedOut }).from(usersTable).where(eq(usersTable.id, req.user.id));
  res.json({ aiAnalysis: !row?.off });
});

router.put("/account/privacy", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const parsed = body.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Send {\"aiAnalysis\": true} or {\"aiAnalysis\": false}." });
    return;
  }
  await db.update(usersTable).set({ aiAnalysisOptedOut: !parsed.data.aiAnalysis }).where(eq(usersTable.id, req.user.id));
  res.json({ aiAnalysis: parsed.data.aiAnalysis });
});

export default router;

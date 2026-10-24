import { Router, type IRouter } from "express";
import { db, reportsTable, reportSharesTable } from "@workspace/db";
import { eq, and, isNull } from "drizzle-orm";
import { z } from "zod";
import { createReportShare, hashShareToken } from "../lib/reportShare";
import { UUID_ANY } from "./accountShared";
import { withNoteFreeTotals } from "../lib/reportTotals";
import { rateLimitMiddleware } from "../lib/rateLimit";
import { getBranding } from "../lib/branding";

const router: IRouter = Router();

// Public and unauthenticated: bound what one address can ask of the database. Tokens are 256 random bits,
// so this is about load rather than guessing.
const shareReadLimit = rateLimitMiddleware({ rules: [{ windowMs: 60_000, max: 120, label: "minute" }], name: "share-read" });

const CreateShareBody = z.object({
  expiresIn: z.enum(["7d", "30d", "never"]).default("never"),
});

// ── POST /api/reports/:id/shares — create a share link ────────────────────────
router.post("/reports/:id/shares", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  if (!reportId || !UUID_ANY.test(reportId)) {
    res.status(404).json({ error: "Report not found" });
    return;
  }
  const parsed = CreateShareBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request" });
    return;
  }

  try {
    const [report] = await db
      .select({ id: reportsTable.id, userId: reportsTable.userId })
      .from(reportsTable)
      .where(eq(reportsTable.id, reportId));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }
    if (report.userId !== req.user!.id) {
      res.status(404).json({ error: "Report not found" });
      return;
    }

    // Ownership is checked above; createReportShare does the minting so the
    // worker's emailed link and this route cannot drift apart.
    const share = await createReportShare(reportId, req.user!.id, parsed.data.expiresIn);

    // The only response that carries the token: the database keeps a hash, so the link cannot be shown again.
    res.status(201).json({
      id: share.id,
      token: share.token,
      expiresAt: share.expiresAt?.toISOString() ?? null,
      createdAt: share.createdAt.toISOString(),
      revokedAt: null,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to create share");
    res.status(500).json({ error: "Failed to create share" });
  }
});

// ── GET /api/reports/:id/shares — list share links for a report ───────────────
router.get("/reports/:id/shares", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  if (!reportId || !UUID_ANY.test(reportId)) {
    res.status(404).json({ error: "Report not found" });
    return;
  }

  try {
    const [report] = await db
      .select({ id: reportsTable.id, userId: reportsTable.userId })
      .from(reportsTable)
      .where(eq(reportsTable.id, reportId));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }
    if (report.userId !== req.user!.id) {
      res.status(404).json({ error: "Report not found" });
      return;
    }

    const shares = await db
      .select()
      .from(reportSharesTable)
      .where(
        and(
          eq(reportSharesTable.reportId, reportId),
          isNull(reportSharesTable.revokedAt),
        ),
      );

    res.json(
      shares.map((s) => ({
        id: s.id,
        expiresAt: s.expiresAt?.toISOString() ?? null,
        createdAt: s.createdAt.toISOString(),
        revokedAt: s.revokedAt?.toISOString() ?? null,
      })),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to list shares");
    res.status(500).json({ error: "Failed to list shares" });
  }
});

// ── DELETE /api/reports/:id/shares/:shareId — revoke a share link ─────────────
router.delete("/reports/:id/shares/:shareId", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  if (!reportId || !UUID_ANY.test(reportId)) {
    res.status(404).json({ error: "Report not found" });
    return;
  }
  const shareId = Array.isArray(req.params.shareId) ? req.params.shareId[0] : req.params.shareId;
  if (!shareId || !UUID_ANY.test(shareId)) {
    res.status(404).json({ error: "Share link not found" });
    return;
  }

  try {
    const [report] = await db
      .select({ id: reportsTable.id, userId: reportsTable.userId })
      .from(reportsTable)
      .where(eq(reportsTable.id, reportId));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }
    if (report.userId !== req.user!.id) {
      res.status(404).json({ error: "Report not found" });
      return;
    }

    const result = await db
      .update(reportSharesTable)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(reportSharesTable.reportId, reportId),
          eq(reportSharesTable.id, shareId),
          isNull(reportSharesTable.revokedAt),
        ),
      )
      .returning({ id: reportSharesTable.id });

    if (result.length === 0) {
      res.status(404).json({ error: "Share link not found" });
      return;
    }

    res.status(204).send();
  } catch (err) {
    req.log.error({ err }, "Failed to revoke share");
    res.status(500).json({ error: "Failed to revoke share" });
  }
});

// ── GET /api/share/:token — public share endpoint (no auth required) ──────────
router.get("/share/:token", shareReadLimit, async (req, res): Promise<void> => {
  const token = Array.isArray(req.params.token) ? req.params.token[0] : req.params.token;

  try {
    const [share] = await db
      .select()
      .from(reportSharesTable)
      .where(
        and(
          eq(reportSharesTable.tokenHash, hashShareToken(token)),
          isNull(reportSharesTable.revokedAt),
        ),
      );

    if (!share) {
      res.status(404).json({ error: "Share link not found or has been revoked" });
      return;
    }

    if (share.expiresAt && share.expiresAt < new Date()) {
      res.status(410).json({ error: "Share link has expired" });
      return;
    }

    const [report] = await db
      .select()
      .from(reportsTable)
      .where(eq(reportsTable.id, share.reportId));

    if (!report) {
      res.status(404).json({ error: "Report not found" });
      return;
    }

    res.json({
      id: report.id,
      scanId: report.scanId,
      targetUrl: report.targetUrl,
      tier: report.tier,
      scannedAt: report.scannedAt,
      duration: report.duration ?? null,
      createdAt: report.createdAt,
      // Totals saved before the notes left them are recounted here (lib/reportTotals.ts).
      data: withNoteFreeTotals(report.data),
      // The owner's report branding, if any: a shared report says who prepared it.
      brand: await getBranding(report.userId),
    });
  } catch (err) {
    req.log.error({ err }, "Failed to fetch shared report");
    res.status(500).json({ error: "Failed to fetch shared report" });
  }
});

export default router;

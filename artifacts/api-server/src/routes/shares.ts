import { Router, type IRouter } from "express";
import { db, reportsTable, reportSharesTable } from "@workspace/db";
import { eq, and, isNull } from "drizzle-orm";
import { randomBytes } from "node:crypto";
import { z } from "zod";

const router: IRouter = Router();

const CreateShareBody = z.object({
  expiresIn: z.enum(["7d", "30d", "never"]).default("never"),
});

function computeExpiry(expiresIn: "7d" | "30d" | "never"): Date | null {
  if (expiresIn === "never") return null;
  const days = expiresIn === "7d" ? 7 : 30;
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d;
}

// ── POST /api/reports/:id/shares — create a share link ────────────────────────
router.post("/reports/:id/shares", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
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
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    const token = randomBytes(32).toString("hex");
    const expiresAt = computeExpiry(parsed.data.expiresIn);

    const [share] = await db
      .insert(reportSharesTable)
      .values({ reportId, userId: req.user!.id, token, expiresAt })
      .returning();

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
      res.status(403).json({ error: "Forbidden" });
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
        token: s.token,
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

// ── DELETE /api/reports/:id/shares/:token — revoke a share link ───────────────
router.delete("/reports/:id/shares/:token", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const token = Array.isArray(req.params.token) ? req.params.token[0] : req.params.token;

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
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    const result = await db
      .update(reportSharesTable)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(reportSharesTable.reportId, reportId),
          eq(reportSharesTable.token, token),
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
router.get("/share/:token", async (req, res): Promise<void> => {
  const token = Array.isArray(req.params.token) ? req.params.token[0] : req.params.token;

  try {
    const [share] = await db
      .select()
      .from(reportSharesTable)
      .where(
        and(
          eq(reportSharesTable.token, token),
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
      data: report.data,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to fetch shared report");
    res.status(500).json({ error: "Failed to fetch shared report" });
  }
});

export default router;

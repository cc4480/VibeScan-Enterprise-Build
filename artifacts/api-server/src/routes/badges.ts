import { Router, type IRouter } from "express";
import { db, reportsTable, reportBadgesTable } from "@workspace/db";
import { eq, and, isNull } from "drizzle-orm";
import { UUID_ANY } from "./accountShared";
import { rateLimitMiddleware } from "../lib/rateLimit";
import { APP_ORIGIN } from "../lib/appOrigin";
import {
  badgeSnippets,
  badgeStateForReport,
  domainVerifiedBy,
  ensureReportBadge,
  isBadgeToken,
  renderBadgeSvg,
  renderMissingBadgeSvg,
  scanRanVerified,
} from "../lib/reportBadge";

const router: IRouter = Router();

// Embedded on other sites, so the address is the reader's. Generous: a README with a few badges is normal.
const badgeReadLimit = rateLimitMiddleware({ rules: [{ windowMs: 60_000, max: 300, label: "minute" }], name: "badge-read" });

/** Owner-only: the report must exist and belong to the caller. Returns null after answering. */
async function ownedReport(
  req: Parameters<Parameters<IRouter["post"]>[1]>[0],
  res: Parameters<Parameters<IRouter["post"]>[1]>[1],
): Promise<{ id: string; targetUrl: string; data: unknown } | null> {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return null;
  }
  const raw = req.params["id"];
  const reportId = Array.isArray(raw) ? raw[0] : raw;
  if (!reportId || !UUID_ANY.test(reportId)) {
    res.status(404).json({ error: "Report not found" });
    return null;
  }
  const [report] = await db
    .select({ id: reportsTable.id, userId: reportsTable.userId, targetUrl: reportsTable.targetUrl, data: reportsTable.data })
    .from(reportsTable)
    .where(eq(reportsTable.id, reportId));
  if (!report) {
    res.status(404).json({ error: "Report not found" });
    return null;
  }
  if (report.userId !== req.user!.id) {
    res.status(404).json({ error: "Report not found" });
    return null;
  }
  return { id: report.id, targetUrl: report.targetUrl, data: report.data };
}

// ── POST /api/reports/:id/badge: get (or create) the report's badge ───────────
//
// Only for a scan of a domain the caller has verified. The badge does not name the site, so
// without this anyone could scan a well-run site they do not own and show its grade as their
// own; and a scan that skipped the active tests would show a grade for half a test.
router.post("/reports/:id/badge", async (req, res): Promise<void> => {
  try {
    const report = await ownedReport(req, res);
    if (!report) return;
    if (!scanRanVerified(report.data) || !(await domainVerifiedBy(req.user!.id, report.targetUrl))) {
      res.status(409).json({
        error:
          "A badge can only be made for a scan of a domain you have verified. Verify the domain, scan it again, and get the badge from that report.",
        code: "badge_needs_verified_scan",
      });
      return;
    }
    const { token } = await ensureReportBadge(report.id, req.user!.id);
    res.status(201).json({ token, ...badgeSnippets(APP_ORIGIN, token) });
  } catch (err) {
    req.log.error({ err }, "Failed to create badge");
    res.status(500).json({ error: "Failed to create badge" });
  }
});

// ── DELETE /api/reports/:id/badge: take the badge down ────────────────────────
router.delete("/reports/:id/badge", async (req, res): Promise<void> => {
  try {
    const report = await ownedReport(req, res);
    if (!report) return;
    await db
      .update(reportBadgesTable)
      .set({ revokedAt: new Date() })
      .where(and(eq(reportBadgesTable.reportId, report.id), isNull(reportBadgesTable.revokedAt)));
    res.status(204).send();
  } catch (err) {
    req.log.error({ err }, "Failed to revoke badge");
    res.status(500).json({ error: "Failed to revoke badge" });
  }
});

// ── GET /api/badge/:token.svg: the public image (no auth) ─────────────────────
//
// Served as an image other sites embed, so three of the headers the rest of /api
// sends have to be overridden: CORP same-origin would stop a badge loading on any
// other site, and no-store would send every README view to the database. The body
// is an SVG with no script, and the CSP below allows nothing but its own inline style.
router.get("/badge/:file", badgeReadLimit, async (req, res): Promise<void> => {
  const raw = req.params["file"];
  const file = Array.isArray(raw) ? raw[0] : raw;
  const token = file?.endsWith(".svg") ? file.slice(0, -4) : "";

  const send = (status: number, svg: string, cache: string): void => {
    res
      .status(status)
      .type("image/svg+xml")
      .set({
        "Cross-Origin-Resource-Policy": "cross-origin",
        "Cache-Control": cache,
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
      })
      .removeHeader("Pragma");
    res.removeHeader("Expires");
    res.send(svg);
  };

  // An unknown, malformed or revoked token all answer the same, so a stranger cannot
  // tell which tokens exist.
  const notFound = (): void => send(404, renderMissingBadgeSvg(), "public, max-age=300");

  if (!isBadgeToken(token)) return notFound();

  try {
    const [badge] = await db
      .select({ reportId: reportBadgesTable.reportId })
      .from(reportBadgesTable)
      .where(and(eq(reportBadgesTable.token, token), isNull(reportBadgesTable.revokedAt)));
    if (!badge) return notFound();

    const [report] = await db
      .select({ data: reportsTable.data, scannedAt: reportsTable.scannedAt })
      .from(reportsTable)
      .where(eq(reportsTable.id, badge.reportId));
    if (!report) return notFound();

    // An hour: long enough that a popular README does not hit the database per view,
    // short enough that a revoked badge is gone the same day. A badge minted before badges
    // needed a verified scan reads "not verified" here rather than showing its grade.
    send(200, renderBadgeSvg(badgeStateForReport(report.data, report.scannedAt)), "public, max-age=3600");
  } catch (err) {
    req.log.error({ err }, "Failed to render badge");
    // Not cached: a database blip must not pin a broken badge in every browser for an hour.
    send(500, renderMissingBadgeSvg(), "no-store");
  }
});

export default router;

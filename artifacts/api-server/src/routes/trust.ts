/**
 * Trust pages. The owner's routes need a signed-in account; the public read does not, and tells a visitor nothing beyond
 * what the page shows. What a page may show, and when it disappears, is in lib/trustPage.ts and lib/trustPageView.ts.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { deleteTrustPage, myTrustPages, publicTrustView, saveTrustPage } from "../lib/trustPage";
import { rateLimitMiddleware } from "../lib/rateLimit";

const router: IRouter = Router();

// Read by strangers and by crawlers; generous, and per address.
const publicReadLimit = rateLimitMiddleware({ rules: [{ windowMs: 60_000, max: 120, label: "minute" }], name: "trust-read" });

const PageBody = z.object({
  displayName: z.string().max(400).nullish(),
  accent: z.string().max(20).nullish(),
  enabled: z.boolean().optional(),
});

router.get("/trust-pages", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  res.setHeader("Cache-Control", "no-store");
  res.json(await myTrustPages(req.user.id));
});

router.put("/trust-pages/:domain", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Sign in to set up a trust page." }); return; }
  const parsed = PageBody.safeParse(req.body ?? {});
  if (!parsed.success) { res.status(400).json({ error: "That is not a valid trust page.", code: "bad_request" }); return; }
  const saved = await saveTrustPage(req.user.id, String(req.params["domain"]), parsed.data);
  if (!saved.ok) { res.status(saved.status).json({ error: saved.message, code: saved.code }); return; }
  req.log.info({ domain: saved.domain }, "Trust page saved");
  res.json({ domain: saved.domain });
});

router.delete("/trust-pages/:domain", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  await deleteTrustPage(req.user.id, String(req.params["domain"]));
  res.json({ deleted: true });
});

/** The public page. One answer for every reason there is nothing to show. */
router.get("/trust/:domain", publicReadLimit, async (req, res): Promise<void> => {
  const view = await publicTrustView(String(req.params["domain"]));
  // A trust page is the owner's to publish; it asks to stay out of search results unless the owner's own site links it.
  res.setHeader("X-Robots-Tag", "noindex");
  if (!view) {
    res.setHeader("Cache-Control", "no-store");
    res.status(404).json({ error: "This trust page is not available." });
    return;
  }
  res.setHeader("Cache-Control", "public, max-age=300");
  res.json(view);
});

export default router;

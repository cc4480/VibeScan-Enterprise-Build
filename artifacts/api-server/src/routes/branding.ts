/**
 * Report branding (Settings, Report branding): the name PDFs and shared reports carry as "prepared by". Signed-in only.
 * The rules for what a name may be are in lib/branding.ts.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { BRAND_MAX, cleanBrandName, getBranding, setBranding } from "../lib/branding";

const router: IRouter = Router();

const Body = z.object({ name: z.string().max(500).nullable(), poweredBy: z.boolean() });

router.get("/account/branding", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  res.setHeader("Cache-Control", "no-store");
  res.json({ brand: await getBranding(req.user.id), max: BRAND_MAX });
});

router.put("/account/branding", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const parsed = Body.safeParse(req.body);
  const name = parsed.success ? cleanBrandName(parsed.data.name) : false;
  if (!parsed.success || name === false) {
    res.status(400).json({ error: `Use a business or team name of up to ${BRAND_MAX} characters, without a web address or email.`, code: "bad_brand" });
    return;
  }
  await setBranding(req.user.id, name, parsed.data.poweredBy);
  res.json({ brand: name ? { name, poweredBy: parsed.data.poweredBy } : null });
});

export default router;

/**
 * GET /scans/:id/live: the tests a running scan has finished, for the progress page.
 *
 * Its own route rather than a field on /scans/:id/status: that response is parsed
 * through a strict generated schema, and anything not in the spec is silently
 * dropped (the same trap that once cost the owner's report its test list).
 * Same access rule as status: only the scan's owner.
 */
import { Router, type IRouter } from "express";
import { and, eq } from "drizzle-orm";
import { db, scansTable } from "@workspace/db";
import { isTestRecord } from "../lib/testLedger";
import { resolveTest } from "../lib/checkOutcomes";
import { TOTAL_CHECKS } from "../lib/checkCatalog";

const router: IRouter = Router();

router.get("/scans/:id/live", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const [scan] = await db
    .select({ status: scansTable.status, liveTests: scansTable.liveTests })
    .from(scansTable)
    .where(and(eq(scansTable.id, rawId), eq(scansTable.userId, req.user.id)));

  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  // Polled every second, and never worth caching: the point is the latest.
  res.setHeader("Cache-Control", "no-store");
  // Each test comes with the checks inside it and what became of each (checkOutcomes.ts),
  // and the total a full scan carries, so the page can show that the two add up.
  const records = Array.isArray(scan.liveTests) ? scan.liveTests.filter(isTestRecord) : [];
  res.json({ status: scan.status, totalChecks: TOTAL_CHECKS, tests: records.map(resolveTest) });
});

export default router;

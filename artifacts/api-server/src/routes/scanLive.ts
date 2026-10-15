/**
 * GET /scans/:id/live: the tests a running scan has finished, for the progress page.
 *
 * Its own route rather than a field on /scans/:id/status: that response is parsed
 * through a strict generated schema, and anything not in the spec is silently
 * dropped (the same trap that once cost the owner's report its test list).
 * Same access rule as status: only the scan's owner.
 */
import { Router, type IRouter } from "express";
import { UUID_ANY } from "./accountShared";
import { and, eq } from "drizzle-orm";
import { db, scansTable } from "@workspace/db";
import { isTestRecord } from "../lib/testLedger";
import { resolveTest } from "../lib/checkOutcomes";
import { REPO_TOTAL_CHECKS, WEBSITE_TOTAL_CHECKS } from "../lib/checkCatalog";
import { repoOnlyAddress } from "../lib/repoOnlyScan";
import { normaliseGithubRepoInput } from "../lib/githubRepoInput";

const router: IRouter = Router();

router.get("/scans/:id/live", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  if (!rawId || !UUID_ANY.test(rawId)) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }
  const [scan] = await db
    .select({ status: scansTable.status, liveTests: scansTable.liveTests, targetUrl: scansTable.targetUrl, githubRepoUrl: scansTable.githubRepoUrl })
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
  // A repository-only scan runs the repository checks and nothing else, so its total is that list alone. A website scan
  // with a repository connected runs both lists, so its total is the sum: the ticker shows the repository steps too.
  const repoOnly = repoOnlyAddress(scan.targetUrl) !== null;
  const connected = normaliseGithubRepoInput(scan.githubRepoUrl);
  const repoUrl = repoOnly ? scan.targetUrl : connected.ok ? connected.url : null;
  const totalChecks = repoOnly ? REPO_TOTAL_CHECKS : WEBSITE_TOTAL_CHECKS + (repoUrl ? REPO_TOTAL_CHECKS : 0);
  // owner/repo of the repository the scan reads, for the ticker's repository lines (null when the scan reads none).
  const repository = repoUrl ? repoUrl.replace(/^https:\/\/github\.com\//i, "").replace(/\/$/, "") : null;
  res.json({ status: scan.status, totalChecks, repository, tests: records.map(resolveTest) });
});

export default router;

/**
 * File findings as GitHub issues: the repository and token an account files them in, and the filing itself.
 * The rules (what is stored, what is redacted, one issue per problem per site) are in lib/githubIssues.ts and
 * lib/githubIssueBody.ts. Signed-in accounts only, and only for findings in the caller's own reports.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { fileIssue, getDestination, issuesForReport, removeDestination, saveDestination } from "../lib/githubIssues";
import { isEncryptionConfigured } from "../lib/crypto";
import { UUID } from "./appRouteRunner";

const router: IRouter = Router();

const DestinationBody = z.object({ repo: z.string().min(3).max(200), token: z.string().min(10).max(300) });
const FileBody = z.object({ findingId: z.string().min(1).max(100) });

router.get("/integrations/github-issues", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  res.setHeader("Cache-Control", "no-store");
  const dest = await getDestination(req.user.id);
  // The token is never returned: only whether one is saved, and for which repository.
  res.json({ configured: dest !== null, repo: dest?.repoFullName ?? null, available: isEncryptionConfigured() });
});

router.put("/integrations/github-issues", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Sign in to connect GitHub issues." }); return; }
  const parsed = DestinationBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: "Enter the repository (owner/name) and the token.", code: "bad_request" }); return; }
  const saved = await saveDestination(req.user.id, parsed.data.repo, parsed.data.token);
  if (!saved.ok) { res.status(saved.status).json({ error: saved.message, code: saved.code }); return; }
  req.log.info({ repo: saved.repoFullName }, "GitHub issue destination saved");
  res.json({ configured: true, repo: saved.repoFullName });
});

router.delete("/integrations/github-issues", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  await removeDestination(req.user.id);
  res.json({ configured: false, repo: null });
});

router.post("/reports/:id/github-issue", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Sign in to file an issue." }); return; }
  const reportId = String(req.params["id"]);
  const parsed = FileBody.safeParse(req.body);
  if (!UUID.test(reportId) || !parsed.success) { res.status(404).json({ error: "That finding was not found in your report.", code: "finding_not_found" }); return; }
  const result = await fileIssue({ userId: req.user.id, reportId, findingId: parsed.data.findingId });
  if (!result.ok) { res.status(result.status).json({ error: result.message, code: result.code }); return; }
  req.log.info({ reportId, issue: result.issueNumber, created: result.created }, "GitHub issue filed");
  res.status(result.created ? 201 : 200).json({ created: result.created, issueNumber: result.issueNumber, issueUrl: result.issueUrl, repo: result.repoFullName });
});

router.get("/reports/:id/github-issues", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const reportId = String(req.params["id"]);
  if (!UUID.test(reportId)) { res.json({ issues: {} }); return; }
  res.setHeader("Cache-Control", "no-store");
  res.json({ issues: await issuesForReport(req.user.id, reportId) });
});

export default router;

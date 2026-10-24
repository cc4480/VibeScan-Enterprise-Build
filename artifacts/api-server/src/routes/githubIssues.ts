/**
 * File findings as GitHub issues: the repository and token an account files them in, and the filing itself.
 * The rules (what is stored, what is redacted, one issue per problem per site) are in lib/githubIssues.ts and
 * lib/githubIssueBody.ts. Signed-in accounts only, and only for findings in the caller's own reports.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { AUTO_SEVERITIES, fileIssue, getDestination, issuesForReport, removeDestination, saveDestination, setAutoFile } from "../lib/githubIssues";
import { isEncryptionConfigured } from "../lib/crypto";
import { UUID } from "./appRouteRunner";
import { actingOwnerForReport } from "../lib/team";

const router: IRouter = Router();

const DestinationBody = z.object({ repo: z.string().min(3).max(200), token: z.string().min(10).max(300) });
const AutoBody = z.object({ enabled: z.boolean(), minSeverity: z.enum(["critical", "high", "medium"]).optional() });
const FileBody = z.object({ findingId: z.string().min(1).max(100) });

router.get("/integrations/github-issues", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  res.setHeader("Cache-Control", "no-store");
  const dest = await getDestination(req.user.id);
  // The token is never returned: only whether one is saved, and for which repository.
  res.json({
    configured: dest !== null, repo: dest?.repoFullName ?? null, available: isEncryptionConfigured(),
    autoFile: dest?.autoFile ?? false, autoMinSeverity: dest?.autoMinSeverity ?? "high",
  });
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

router.patch("/integrations/github-issues/auto", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const parsed = AutoBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: `Send { "enabled": true or false, "minSeverity": ${AUTO_SEVERITIES.map((s) => `"${s}"`).join(", ")} }.`, code: "bad_request" }); return; }
  const current = await getDestination(req.user.id);
  if (!current) { res.status(409).json({ error: "Connect a GitHub repository first.", code: "no_destination" }); return; }
  const minSeverity = parsed.data.minSeverity ?? current.autoMinSeverity;
  await setAutoFile(req.user.id, parsed.data.enabled, minSeverity);
  res.json({ autoFile: parsed.data.enabled, autoMinSeverity: minSeverity });
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
  // Their own report, or the owner's when the caller is an editor on the owner's team.
  const ownerId = await actingOwnerForReport(req.user.id, reportId);
  if (!ownerId) { res.status(404).json({ error: "That finding was not found in your report.", code: "finding_not_found" }); return; }
  const result = await fileIssue({ userId: ownerId, reportId, findingId: parsed.data.findingId });
  if (!result.ok) { res.status(result.status).json({ error: result.message, code: result.code }); return; }
  req.log.info({ reportId, issue: result.issueNumber, created: result.created }, "GitHub issue filed");
  res.status(result.created ? 201 : 200).json({ created: result.created, issueNumber: result.issueNumber, issueUrl: result.issueUrl, repo: result.repoFullName });
});

router.get("/reports/:id/github-issues", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const reportId = String(req.params["id"]);
  if (!UUID.test(reportId)) { res.json({ issues: {} }); return; }
  res.setHeader("Cache-Control", "no-store");
  const ownerId = await actingOwnerForReport(req.user.id, reportId);
  if (!ownerId) { res.json({ issues: {}, destination: null }); return; }
  // The destination is the owner's, so an editor sees where the report's issues go without being given anything else.
  const dest = await getDestination(ownerId);
  res.json({ issues: await issuesForReport(ownerId, reportId), destination: dest ? { configured: true, repo: dest.repoFullName, available: isEncryptionConfigured() } : { configured: false, repo: null, available: isEncryptionConfigured() } });
});

export default router;

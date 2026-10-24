/**
 * File findings as Linear issues or Jira tickets: where an account files them, and the filing itself.
 * The rules (what is stored, what is redacted, one ticket per problem per site) are in lib/tickets.ts and lib/ticketBody.ts.
 * Signed-in accounts only, and only for findings in the caller's own reports.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { AUTO_SEVERITIES, PROVIDERS, fileTicket, getDestination, getDestinations, removeDestination, saveDestination, setAutoFile, ticketsForReport, type Provider } from "../lib/tickets";
import { isEncryptionConfigured } from "../lib/crypto";
import { UUID } from "./appRouteRunner";
import { actingOwnerForReport } from "../lib/team";

const router: IRouter = Router();

const LinearBody = z.object({ team: z.string().min(1).max(20), apiKey: z.string().min(10).max(300) });
const JiraBody = z.object({
  site: z.string().min(1).max(200), email: z.string().min(3).max(320), token: z.string().min(10).max(400),
  project: z.string().min(2).max(20), issueType: z.string().max(60).optional(),
});
const AutoBody = z.object({ enabled: z.boolean(), minSeverity: z.enum(["critical", "high", "medium"]).optional() });
const FileBody = z.object({ provider: z.enum(["linear", "jira"]), findingId: z.string().min(1).max(100) });

const providerOf = (v: unknown): Provider | null => (PROVIDERS as readonly string[]).includes(String(v)) ? (String(v) as Provider) : null;

router.get("/integrations/tickets", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  res.setHeader("Cache-Control", "no-store");
  // The credential is never returned: only whether one is saved, and for where.
  res.json({ available: isEncryptionConfigured(), destinations: await getDestinations(req.user.id) });
});

router.put("/integrations/tickets/:provider", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Sign in to connect Linear or Jira." }); return; }
  const provider = providerOf(req.params["provider"]);
  if (!provider) { res.status(404).json({ error: "Unknown ticket system.", code: "unknown_provider" }); return; }
  const parsed = provider === "linear" ? LinearBody.safeParse(req.body) : JiraBody.safeParse(req.body);
  if (!parsed.success) {
    const what = provider === "linear" ? "the team key and the API key" : "the site, your email, the API token and the project key";
    res.status(400).json({ error: `Enter ${what}.`, code: "bad_request" });
    return;
  }
  const saved = await saveDestination(req.user.id, provider === "linear"
    ? { provider, ...(parsed.data as z.infer<typeof LinearBody>) }
    : { provider, ...(parsed.data as z.infer<typeof JiraBody>) });
  if (!saved.ok) { res.status(saved.status).json({ error: saved.message, code: saved.code }); return; }
  req.log.info({ provider, target: saved.target }, "Ticket destination saved");
  res.json({ configured: true, provider, target: saved.target });
});

router.patch("/integrations/tickets/:provider/auto", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const provider = providerOf(req.params["provider"]);
  if (!provider) { res.status(404).json({ error: "Unknown ticket system.", code: "unknown_provider" }); return; }
  const parsed = AutoBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: `Send { "enabled": true or false, "minSeverity": ${AUTO_SEVERITIES.map((s) => `"${s}"`).join(", ")} }.`, code: "bad_request" }); return; }
  const current = await getDestination(req.user.id, provider);
  if (!current) { res.status(409).json({ error: "Connect it first.", code: "no_destination" }); return; }
  const minSeverity = parsed.data.minSeverity ?? current.autoMinSeverity;
  await setAutoFile(req.user.id, provider, parsed.data.enabled, minSeverity);
  res.json({ autoFile: parsed.data.enabled, autoMinSeverity: minSeverity });
});

router.delete("/integrations/tickets/:provider", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const provider = providerOf(req.params["provider"]);
  if (!provider) { res.status(404).json({ error: "Unknown ticket system.", code: "unknown_provider" }); return; }
  await removeDestination(req.user.id, provider);
  res.json({ configured: false });
});

router.post("/reports/:id/ticket", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Sign in to file a ticket." }); return; }
  const reportId = String(req.params["id"]);
  const parsed = FileBody.safeParse(req.body);
  if (!UUID.test(reportId) || !parsed.success) { res.status(404).json({ error: "That finding was not found in your report.", code: "finding_not_found" }); return; }
  // Their own report, or the owner's when the caller is an editor on the owner's team.
  const ownerId = await actingOwnerForReport(req.user.id, reportId);
  if (!ownerId) { res.status(404).json({ error: "That finding was not found in your report.", code: "finding_not_found" }); return; }
  const result = await fileTicket({ userId: ownerId, provider: parsed.data.provider, reportId, findingId: parsed.data.findingId });
  if (!result.ok) { res.status(result.status).json({ error: result.message, code: result.code }); return; }
  req.log.info({ reportId, provider: result.provider, ticket: result.ticketKey, created: result.created }, "Ticket filed");
  res.status(result.created ? 201 : 200).json({ created: result.created, provider: result.provider, ticketKey: result.ticketKey, ticketUrl: result.ticketUrl });
});

router.get("/reports/:id/tickets", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const reportId = String(req.params["id"]);
  if (!UUID.test(reportId)) { res.json({ tickets: {} }); return; }
  res.setHeader("Cache-Control", "no-store");
  const ownerId = await actingOwnerForReport(req.user.id, reportId);
  if (!ownerId) { res.json({ tickets: {}, destinations: [] }); return; }
  // The destinations are the owner's: an editor learns where a ticket would go, never the credential (it is not in this list).
  res.json({ tickets: await ticketsForReport(ownerId, reportId), destinations: await getDestinations(ownerId) });
});

export default router;

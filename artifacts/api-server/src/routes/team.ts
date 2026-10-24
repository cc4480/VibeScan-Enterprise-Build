/**
 * Teams as shared viewing: invite teammates, accept an invitation, see and leave the teams you are on, and read a team
 * owner's reports. The rules (what a teammate can and cannot do, how an invitation is bound to an address) are in lib/team.ts.
 * Every route needs a signed-in account.
 */
import { Router, type IRouter } from "express";
import { z } from "zod";
import { acceptInvite, inviteMember, leaveTeam, listTeam, MAX_TEAM, removeMember, roleOf, setRole, sharedReports, sharedWithMe } from "../lib/team";
import { sharedMonitors } from "../lib/teamMonitors";
import { sendTeamInviteEmail } from "../lib/mailer";
import { rateLimitMiddleware } from "../lib/rateLimit";
import { UUID } from "./appRouteRunner";

const router: IRouter = Router();

// Per account, not per address: a whole office shares one. TEAM_INVITES_PER_HOUR changes the cap (default 30).
const inviteLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60 * 60_000, max: Number(process.env["TEAM_INVITES_PER_HOUR"]) || 30, label: "hour" }],
  name: "team-invite",
  keyFrom: (req) => (req.isAuthenticated() ? `user:${req.user.id}` : undefined),
});
// A signed-in action, so per account too. The token is 256 random bits, so this is about noise, not guessing.
const acceptLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60_000, max: Number(process.env["TEAM_ACCEPTS_PER_MINUTE"]) || 20, label: "minute" }],
  name: "team-accept",
  keyFrom: (req) => (req.isAuthenticated() ? `user:${req.user.id}` : undefined),
});

const InviteBody = z.object({ email: z.string().max(300), role: z.enum(["viewer", "editor"]).optional() });
const RoleBody = z.object({ role: z.enum(["viewer", "editor"]) });
const AcceptBody = z.object({ token: z.string().max(200) });

router.get("/team", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  res.setHeader("Cache-Control", "no-store");
  res.json({ members: await listTeam(req.user.id), max: MAX_TEAM });
});

router.post("/team/invites", inviteLimit, async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Sign in to invite a teammate." }); return; }
  if (!req.user.email) { res.status(400).json({ error: "Add an email address to your account before inviting a teammate.", code: "no_owner_email" }); return; }
  const parsed = InviteBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: "Enter the teammate's email address.", code: "bad_email" }); return; }
  const invited = await inviteMember(req.user.id, req.user.email, parsed.data.email, roleOf(parsed.data.role));
  if (!invited.ok) { res.status(invited.status).json({ error: invited.message, code: invited.code }); return; }
  try {
    await sendTeamInviteEmail(invited.email, req.user.email, invited.url, roleOf(parsed.data.role));
  } catch (err) {
    // The mailer reports most failures itself; this is the rare one it does not. The link below still works.
    req.log.warn({ err }, "Team invitation email could not be sent");
  }
  req.log.info({ resent: invited.resent }, "Team invitation created");
  // The link is returned to the owner too: it only works for the invited address, and mail can fail or land in spam.
  res.status(invited.resent ? 200 : 201).json({ email: invited.email, resent: invited.resent, inviteUrl: invited.url });
});

router.patch("/team/members/:id/role", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const id = String(req.params["id"]);
  const parsed = RoleBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: "Choose viewer or editor.", code: "bad_role" }); return; }
  const changed = UUID.test(id) && (await setRole(req.user.id, id, parsed.data.role));
  if (!changed) { res.status(404).json({ error: "That person is not on your team." }); return; }
  res.json({ role: parsed.data.role });
});

router.delete("/team/members/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const id = String(req.params["id"]);
  const removed = UUID.test(id) && (await removeMember(req.user.id, id));
  if (!removed) { res.status(404).json({ error: "That person is not on your team." }); return; }
  res.json({ removed: true });
});

router.post("/team/accept", acceptLimit, async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Sign in to accept the invitation." }); return; }
  const parsed = AcceptBody.safeParse(req.body);
  const accepted = await acceptInvite(req.user.id, req.user.email, parsed.success ? parsed.data.token : "");
  if (!accepted.ok) { res.status(accepted.status).json({ error: accepted.message, code: accepted.code }); return; }
  req.log.info("Team invitation accepted");
  res.json({ accepted: true });
});

router.get("/team/shared", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  res.setHeader("Cache-Control", "no-store");
  res.json({ teams: await sharedWithMe(req.user.id) });
});

router.delete("/team/shared/:id", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const id = String(req.params["id"]);
  const left = UUID.test(id) && (await leaveTeam(req.user.id, id));
  if (!left) { res.status(404).json({ error: "You are not on that team." }); return; }
  res.json({ left: true });
});

router.get("/team/shared/:id/reports", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const id = String(req.params["id"]);
  const reports = UUID.test(id) ? await sharedReports(req.user.id, id) : null;
  // One answer for a team you are not on and one that does not exist.
  if (!reports) { res.status(404).json({ error: "Not found." }); return; }
  res.setHeader("Cache-Control", "no-store");
  res.json({ reports });
});

router.get("/team/shared/:id/monitors", async (req, res): Promise<void> => {
  if (!req.isAuthenticated()) { res.status(401).json({ error: "Unauthorized" }); return; }
  const id = String(req.params["id"]);
  const monitors = UUID.test(id) ? await sharedMonitors(req.user.id, id) : null;
  if (!monitors) { res.status(404).json({ error: "Not found." }); return; }
  res.setHeader("Cache-Control", "no-store");
  res.json({ monitors });
});

export default router;

/**
 * The person's side of OAuth: check an authorization request, record their decision,
 * and manage the apps they have connected. Every route here needs a signed-in,
 * registered account (session cookie, SameSite=lax), and none allows cross-origin
 * calls: an approval must come from this site's own page.
 *
 * Order of trust. The server, not the page, checks the request: the app must be
 * registered and the redirect address must match one it registered EXACTLY. If
 * either is wrong the person is told and NOT redirected (redirecting to an
 * unverified address is how an authorization code is stolen). Anything else wrong
 * with a request from a real app goes back to that app as a standard error.
 * Approval must carry the signed consent token issued for this exact request and
 * this user (lib/oauthConsent.ts).
 */
import { Router, type IRouter, type Request, type Response } from "express";
import { rateLimitMiddleware } from "../lib/rateLimit";
import { APP_ORIGIN } from "../lib/appOrigin";
import { describeRedirect, findClient, redirectUriAllowed } from "../lib/oauthClients";
import { isValidChallenge } from "../lib/oauthPkce";
import { signConsent, verifyConsent } from "../lib/oauthConsent";
import { disconnectApp, issueAuthorizationCode, listConnections } from "../lib/oauthTokens";
import { MCP_RESOURCE } from "./oauthMetadata";

const router: IRouter = Router();

const decisionLimit = rateLimitMiddleware({
  rules: [{ windowMs: 3_600_000, max: 30, label: "hour" }],
  name: "oauth-decision",
  keyFrom: (req) => (req.isAuthenticated() ? `oauth-decision:${req.user.id}` : undefined),
});

const MAX_STATE = 500;
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

/** The address to send the person back to: the app's own URL plus standard parameters (and iss, RFC 9207). */
export function redirectWith(uri: string, params: Record<string, string | null>): string {
  const url = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v !== null) url.searchParams.set(k, v);
  url.searchParams.set("iss", APP_ORIGIN);
  return url.toString();
}

function requireAccount(req: Request, res: Response): req is Request & { user: { id: string; email: string } } {
  if (!req.isAuthenticated() || !req.user.email) {
    res.status(401).json({ error: "login_required", error_description: "Sign in to continue." });
    return false;
  }
  return true;
}

router.get("/oauth/authorize/preview", async (req: Request, res: Response): Promise<void> => {
  if (!requireAccount(req, res)) return;
  const q = req.query as Record<string, unknown>;

  // 1. Who is asking, and where would we send the answer? Wrong here means no redirect.
  const client = await findClient(q["client_id"]);
  if (!client) {
    res.status(400).json({ error: "invalid_client", error_description: "This app is not registered." });
    return;
  }
  const redirectUri = q["redirect_uri"];
  if (!redirectUriAllowed(client, redirectUri)) {
    res.status(400).json({ error: "invalid_redirect_uri", error_description: "This app asked to return to an address it did not register." });
    return;
  }

  // 2. Anything else wrong goes back to the app, as the standard says.
  const state = str(q["state"]);
  const back = (error: string, description: string): void => {
    res.json({ redirectUrl: redirectWith(redirectUri, { error, error_description: description, state }) });
  };
  if (state !== null && state.length > MAX_STATE) return back("invalid_request", "state is too long.");
  if (q["response_type"] !== "code") return back("unsupported_response_type", "Only response_type=code is supported.");
  if (q["code_challenge_method"] !== "S256" || !isValidChallenge(q["code_challenge"])) return back("invalid_request", "PKCE with code_challenge_method=S256 is required.");
  const scope = str(q["scope"]);
  if (scope !== null && scope.split(/\s+/).filter(Boolean).some((s) => s !== "mcp")) return back("invalid_scope", "The only scope is mcp.");
  const resource = str(q["resource"]);
  if (resource !== null && resource.replace(/\/$/, "") !== MCP_RESOURCE) return back("invalid_target", "resource must be the SecScan MCP endpoint.");

  res.setHeader("Cache-Control", "no-store");
  res.json({
    client: { name: client.name },
    redirect: describeRedirect(redirectUri),
    account: req.user.email,
    // Exactly what the MCP tools do (routes/mcp.ts): nothing about billing, settings or tokens.
    access: [
      "Start scans of your sites (they use your free scans, plan scans or credits)",
      "Read scan reports and the fixes for them",
      "Add and run monitors, and verify domains you own",
      "Mark a finding as a false positive when you tell it to",
      "See how many scans you have left",
    ],
    consent: signConsent({ userId: req.user.id, clientId: client.clientId, redirectUri, codeChallenge: q["code_challenge"] as string, state }),
  });
});

router.post("/oauth/authorize/decision", async (req: Request, res: Response): Promise<void> => {
  if (!requireAccount(req, res)) return;
  const body = (req.body ?? {}) as Record<string, unknown>;
  const consent = verifyConsent(body["consent"], req.user.id);
  if (!consent) {
    res.status(400).json({ error: "invalid_request", error_description: "This approval has expired. Start again from your app." });
    return;
  }
  const decision = decisionLimit.decide(req);
  if (!decision.allowed) {
    res.status(429).setHeader("Retry-After", String(decision.retryAfterSeconds ?? 60)).json({ error: "temporarily_unavailable", error_description: "Too many approvals. Try again later." });
    return;
  }
  // The app must still exist and still own that redirect address.
  const client = await findClient(consent.clientId);
  if (!client || !redirectUriAllowed(client, consent.redirectUri)) {
    res.status(400).json({ error: "invalid_client", error_description: "This app is no longer registered." });
    return;
  }

  if (body["approve"] !== true) {
    res.json({ redirectUrl: redirectWith(consent.redirectUri, { error: "access_denied", error_description: "The user declined.", state: consent.state }) });
    return;
  }
  const code = await issueAuthorizationCode({ userId: req.user.id, clientId: client.clientId, redirectUri: consent.redirectUri, codeChallenge: consent.codeChallenge });
  req.log.info({ clientId: client.clientId }, "OAuth authorization approved");
  res.json({ redirectUrl: redirectWith(consent.redirectUri, { code, state: consent.state }) });
});

router.get("/account/connections", async (req: Request, res: Response): Promise<void> => {
  if (!requireAccount(req, res)) return;
  res.json({ connections: await listConnections(req.user.id) });
});

router.delete("/account/connections/:clientId", async (req: Request, res: Response): Promise<void> => {
  if (!requireAccount(req, res)) return;
  const clientId = String(req.params["clientId"]);
  if (!/^mcp_[A-Za-z0-9_-]{20,40}$/.test(clientId)) {
    res.status(404).json({ error: "Connection not found." });
    return;
  }
  // Scoped to the owner: another user's connection revokes nothing and looks like any unknown id.
  const revoked = await disconnectApp(req.user.id, clientId);
  if (revoked === 0) {
    res.status(404).json({ error: "Connection not found." });
    return;
  }
  req.log.info({ clientId }, "OAuth connection removed");
  res.status(204).end();
});

export default router;

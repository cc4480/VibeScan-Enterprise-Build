/**
 * The OAuth endpoints an app calls directly, with no browser session: registering
 * itself, trading a code or refresh token for tokens, and revoking. See
 * lib/oauthTokens.ts for the rules and routes/oauthConsent.ts for the person's side.
 *
 * Errors follow RFC 6749: HTTP 400 with { error, error_description }, and never a
 * hint about WHICH thing was wrong beyond what the standard names. Nothing here
 * returns a token in a URL, and every token response says not to cache it.
 */
import { Router, type IRouter, type Response } from "express";
import { rateLimitMiddleware } from "../lib/rateLimit";
import { findClient, registerClient, validateRegistration } from "../lib/oauthClients";
import { exchangeCode, refreshTokens, revokeByToken } from "../lib/oauthTokens";

const router: IRouter = Router();

// Registration is open by design, so it is the thing to bound. It grants nothing by
// itself: a person must still sign in and approve each connection.
const registerLimit = rateLimitMiddleware({ rules: [{ windowMs: 3_600_000, max: 20, label: "hour" }], name: "oauth-register" });
const tokenLimit = rateLimitMiddleware({ rules: [{ windowMs: 60_000, max: 60, label: "minute" }], name: "oauth-token" });

function oauthError(res: Response, status: number, error: string, description: string): void {
  res.status(status).setHeader("Cache-Control", "no-store").json({ error, error_description: description });
}

function limited(res: Response, decision: { allowed: boolean; retryAfterSeconds?: number }): boolean {
  if (decision.allowed) return false;
  res.setHeader("Retry-After", String(decision.retryAfterSeconds ?? 60));
  oauthError(res, 429, "temporarily_unavailable", "Too many requests. Try again shortly.");
  return true;
}

router.post("/oauth/register", async (req, res): Promise<void> => {
  if (limited(res, registerLimit.decide(req))) return;
  const result = validateRegistration((req.body ?? {}) as Record<string, unknown>);
  if (!result.ok) {
    oauthError(res, 400, result.error, result.description);
    return;
  }
  const client = await registerClient(result.name, result.redirectUris);
  req.log.info({ clientName: client.name }, "OAuth client registered");
  res.status(201).setHeader("Cache-Control", "no-store").json({
    client_id: client.clientId,
    client_name: client.name,
    redirect_uris: client.redirectUris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    client_id_issued_at: Math.floor(Date.now() / 1000),
  });
});

router.post("/oauth/token", async (req, res): Promise<void> => {
  if (limited(res, tokenLimit.decide(req))) return;
  // Form-encoded per the standard; JSON is accepted because some clients send it.
  const body = (req.body ?? {}) as Record<string, unknown>;

  const client = await findClient(body["client_id"]);
  if (!client) {
    oauthError(res, 401, "invalid_client", "Unknown client_id. Register the app first.");
    return;
  }

  let result;
  if (body["grant_type"] === "authorization_code") {
    result = await exchangeCode({ code: body["code"], clientId: client.clientId, redirectUri: body["redirect_uri"], codeVerifier: body["code_verifier"] });
  } else if (body["grant_type"] === "refresh_token") {
    result = await refreshTokens({ refreshToken: body["refresh_token"], clientId: client.clientId });
  } else {
    oauthError(res, 400, "unsupported_grant_type", "Use authorization_code or refresh_token.");
    return;
  }

  if (!result.ok) {
    oauthError(res, 400, result.error, result.description);
    return;
  }
  res.status(200).setHeader("Cache-Control", "no-store").setHeader("Pragma", "no-cache").json(result.tokens);
});

// RFC 7009: always 200, so the response never says whether a token existed.
router.post("/oauth/revoke", async (req, res): Promise<void> => {
  if (limited(res, tokenLimit.decide(req))) return;
  await revokeByToken((req.body as Record<string, unknown> | undefined)?.["token"]);
  res.status(200).setHeader("Cache-Control", "no-store").json({});
});

export default router;

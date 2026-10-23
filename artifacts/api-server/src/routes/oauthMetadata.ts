/**
 * OAuth discovery documents, at the site root (not under /api) as the standards
 * require. An MCP client that gets a 401 from /api/mcp follows the WWW-Authenticate
 * header to the protected-resource document, from there to the authorization-server
 * document, and then knows where to register, send the person, and fetch tokens.
 *
 *   RFC 9728  /.well-known/oauth-protected-resource[/api/mcp]
 *   RFC 8414  /.well-known/oauth-authorization-server
 *
 * Public and identical for everyone, so they carry Access-Control-Allow-Origin: *.
 */
import { Router, type IRouter } from "express";
import { APP_ORIGIN } from "../lib/appOrigin";

const router: IRouter = Router();

export const MCP_RESOURCE = `${APP_ORIGIN}/api/mcp`;
export const PROTECTED_RESOURCE_URL = `${APP_ORIGIN}/.well-known/oauth-protected-resource/api/mcp`;

export const AUTHORIZATION_SERVER = {
  issuer: APP_ORIGIN,
  authorization_endpoint: `${APP_ORIGIN}/oauth/authorize`,
  token_endpoint: `${APP_ORIGIN}/api/oauth/token`,
  registration_endpoint: `${APP_ORIGIN}/api/oauth/register`,
  revocation_endpoint: `${APP_ORIGIN}/api/oauth/revoke`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  // S256 only: "plain" would send the secret in the clear.
  code_challenge_methods_supported: ["S256"],
  // Public clients: an editor on a laptop holds no secret, PKCE is the proof.
  token_endpoint_auth_methods_supported: ["none"],
  scopes_supported: ["mcp"],
  service_documentation: "https://secscan.info/ai-editors",
} as const;

export const PROTECTED_RESOURCE = {
  resource: MCP_RESOURCE,
  authorization_servers: [APP_ORIGIN],
  bearer_methods_supported: ["header"],
  scopes_supported: ["mcp"],
  resource_name: "SecScan MCP",
} as const;

const publicJson = (res: import("express").Response, body: unknown) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.json(body);
};

router.get("/.well-known/oauth-authorization-server", (_req, res) => publicJson(res, AUTHORIZATION_SERVER));
router.get("/.well-known/oauth-protected-resource", (_req, res) => publicJson(res, PROTECTED_RESOURCE));
// RFC 9728 puts the resource's path after the well-known name; some clients ask for it that way.
router.get("/.well-known/oauth-protected-resource/api/mcp", (_req, res) => publicJson(res, PROTECTED_RESOURCE));

export default router;

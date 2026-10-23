import { registerScanTools } from "./mcpScanTools";
import { registerAccountTools } from "./mcpAccountTools";
import { registerMonitorTools } from "./mcpMonitorTools";
import { formatReport, formatAccount, formatVerification, formatMonitors, SERVER_INSTRUCTIONS, type ReportPage } from "./mcpFormat";
import { Router, type IRouter, type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { and } from "drizzle-orm";
import { authenticateApiToken, type TokenUser } from "../lib/apiTokens";
import { PROTECTED_RESOURCE_URL } from "./oauthMetadata";
import { APP_ORIGIN } from "../lib/appOrigin";
import { rateLimitMiddleware } from "../lib/rateLimit";

/**
 * Remote MCP endpoint — lets an AI editor (Claude Code, Cursor, …) scan a site
 * and read the findings without the user leaving it.
 *
 *   claude mcp add --transport http secscan https://secscan.us/api/mcp \
 *     --header "Authorization: Bearer ssk_…"
 *
 * Stateless Streamable HTTP: a fresh server per request, bound to the user the
 * API token belongs to. Nothing is held between requests, so it runs on every
 * replica with no session affinity.
 *
 * The one rule this file exists to keep: NO SIDE DOOR. scan_url does not launch
 * scans itself — it runs the website's own handler (createScanHandler) after
 * the website's own rate limiters, so the free trial, credits and plan scans,
 * the SSRF guard, domain-ownership gating of active tests and every validation
 * apply exactly as they do in the browser. Reads are scoped to the token's
 * owner in every query.
 */


















export { formatReport, formatAccount, formatVerification, formatMonitors } from "./mcpFormat";
export type { ReportPage } from "./mcpFormat";

const router: IRouter = Router();

/**
 * Requests per user per minute, across all tools. Scans already have their own
 * (stricter) limits; this bounds the reads — an editor stuck in a loop calling
 * get_report should not be able to hammer the database. A normal session makes
 * a handful of calls a minute.
 */
const mcpRateLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60_000, max: 120, label: "minute" }],
  name: "mcp",
  keyFrom: (req) => (req.isAuthenticated() ? `mcp:${req.user.id}` : undefined),
});

/**
 * Exported so the public server card (scripts/build-server-card.ts) is built
 * from these exact tool definitions, and a test can catch the two drifting.
 * Listing tools never touches the user or the request; only calling one does.
 */
export function buildServer(httpReq: Request, user: TokenUser): McpServer {
  const server = new McpServer({ name: "secscan", version: "1.1.0" }, { instructions: SERVER_INSTRUCTIONS });

  registerScanTools(server, httpReq, user);
  registerAccountTools(server, httpReq, user);
  registerMonitorTools(server, httpReq, user);

  return server;
}

/**
 * JSON-RPC methods answered without a token: the handshake and the tool list.
 *
 * Directories (Glama, Smithery, the MCP Registry) health-check a server by
 * connecting and listing its tools. With every request behind a token they got
 * a 401, marked the connector "Unhealthy", and a list would not accept it. The
 * tool names and descriptions are already public (server-card.json and
 * secscan.info/ai-editors), so listing them reveals nothing new.
 *
 * Calling a tool is NOT here and never may be: every tools/call still needs a
 * token, because each one reads or spends something that belongs to a user.
 */
const PUBLIC_METHODS = new Set(["initialize", "notifications/initialized", "ping", "tools/list"]);

/**
 * True only when EVERY message in the body is a public method. A batch that
 * slips one tools/call in among public ones is refused whole. Exported for tests.
 */
export function isPublicMcpRequest(body: unknown): boolean {
  const messages = Array.isArray(body) ? body : [body];
  return (
    messages.length > 0 &&
    messages.every(
      (m) =>
        m !== null &&
        typeof m === "object" &&
        typeof (m as { method?: unknown }).method === "string" &&
        PUBLIC_METHODS.has((m as { method: string }).method),
    )
  );
}

/** Tokenless handshakes and tool listings, per IP. A health check makes a few a minute. */
const mcpPublicRateLimit = rateLimitMiddleware({
  rules: [{ windowMs: 60_000, max: 30, label: "minute" }],
  name: "mcp-public",
});

/**
 * Stands in for a user on tokenless requests. It can only ever reach
 * initialize/ping/tools/list (isPublicMcpRequest gates the body), none of
 * which touch the user — the same placeholder serverCard.ts builds with.
 */
const ANONYMOUS = { id: "anonymous", email: null } as never as TokenUser;

async function serve(req: Request, res: Response, server: McpServer): Promise<void> {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    req.log.error({ err }, "MCP request failed");
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  }
}

router.post("/mcp", async (req, res): Promise<void> => {
  const user = await authenticateApiToken(req.headers["authorization"]);
  if (!user) {
    if (!isPublicMcpRequest(req.body)) {
      res
        .status(401)
        // resource_metadata (RFC 9728) tells an OAuth-capable client where to sign the person in.
        .setHeader("WWW-Authenticate", `Bearer realm="secscan", resource_metadata="${PROTECTED_RESOURCE_URL}"`)
        .json({ error: `Missing or invalid API token. Create one at ${APP_ORIGIN}/settings#ai-editors.` });
      return;
    }
    const publicDecision = mcpPublicRateLimit.decide(req);
    if (!publicDecision.allowed) {
      res
        .status(429)
        .setHeader("Retry-After", String(publicDecision.retryAfterSeconds ?? 60))
        .json({ error: "Too many requests. Try again in a minute." });
      return;
    }
    await serve(req, res, buildServer(req, ANONYMOUS));
    return;
  }

  // Per-user request budget, checked after authentication so it counts
  // against the account rather than the address.
  const decision = mcpRateLimit.decide(Object.assign(Object.create(req), { user, isAuthenticated: () => true }) as Request);
  if (!decision.allowed) {
    res
      .status(429)
      .setHeader("Retry-After", String(decision.retryAfterSeconds ?? 60))
      .json({ error: `Too many requests — at most ${decision.rule?.max} per ${decision.rule?.label}. Try again in ${decision.retryAfterSeconds} seconds.` });
    return;
  }

  await serve(req, res, buildServer(req, user));
});

// Stateless: there is no server-initiated stream to open and no session to end.
router.get("/mcp", (_req, res) => {
  res.status(405).setHeader("Allow", "POST").json({ error: "Use POST." });
});
router.delete("/mcp", (_req, res) => {
  res.status(405).setHeader("Allow", "POST").json({ error: "Use POST." });
});

export default router;
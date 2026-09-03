/**
 * Out-of-band callback endpoint.
 *
 * This is what a target's server hits when an injected URL causes it to make a
 * request — an SSRF fetch, a blind-XSS beacon, a webhook resolving our host. It
 * is deliberately unauthenticated: the caller is someone else's server, not a
 * signed-in user, and it cannot present a session.
 *
 * Every method and any sub-path under the token is accepted, because an SSRF
 * payload has no reason to use GET or to leave the path clean. The response is
 * always a bare 200 with no body, whether or not the token was real, so the
 * endpoint reveals nothing to someone probing it directly.
 */

import { Router, type IRouter, type Request, type Response } from "express";
import { recordOobInteraction } from "../lib/oobServer";

const router: IRouter = Router();

function clientIp(req: Request): string {
  return String(
    req.headers["x-forwarded-for"] ?? req.socket.remoteAddress ?? "",
  ).split(",")[0]!.trim();
}

async function handle(req: Request, res: Response): Promise<void> {
  const raw = req.params["token"];
  const token = Array.isArray(raw) ? raw[0] : raw;
  if (token) {
    // Best-effort: a logging failure must not turn into a 500 that a scanned
    // target might interpret, or that reveals the endpoint is special.
    await recordOobInteraction(token, {
      method: req.method,
      path: req.originalUrl,
      sourceIp: clientIp(req),
      userAgent: typeof req.headers["user-agent"] === "string" ? req.headers["user-agent"] : undefined,
    }).catch(() => undefined);
  }
  res.status(200).end();
}

// The token, then anything after it — SSRF payloads append their own paths.
router.all("/oob/:token", handle);
router.all("/oob/:token/*splat", handle);

export default router;

/**
 * Caller identity for rate limiting.
 *
 * Client tokens are self-minted UUIDs (see authMiddleware) — a caller can mint
 * a fresh identity per request, so per-user limits are unenforceable and the
 * address is the only thing worth counting against.
 *
 * That makes trusting the right address load-bearing. Two ways to get it wrong:
 *
 *   - Trust X-Forwarded-For blindly, and any client sets their own header to
 *     whatever they like and bypasses the limit entirely. This is how the
 *     original login limiter in auth.ts read the header.
 *   - Trust nothing, and behind a reverse proxy every request appears to come
 *     from the proxy, so one bucket holds every user on the internet.
 *
 * The deployment answers this with TRUST_PROXY (see configureTrustProxy): the
 * number of reverse proxies actually in front of the app. Express then resolves
 * req.ip by discarding exactly that many hops, and everything here uses req.ip
 * rather than reading headers directly. deploy/Caddyfile additionally overwrites
 * X-Forwarded-For with the real peer, so a spoofed header never survives the
 * proxy in the first place.
 */

import type { Express, Request } from "express";
import { logger } from "./logger";

/**
 * Apply the deployment's proxy topology to Express.
 *
 * TRUST_PROXY accepts a hop count ("1"), "true"/"false", or a comma-separated
 * list of trusted addresses/CIDRs, matching Express's own `trust proxy` values.
 * Defaults to 1 in production — the shipped compose stack puts Caddy in front —
 * and 0 in development, where the API is reached directly.
 *
 * `true` is deliberately not the default: it trusts the leftmost X-Forwarded-For
 * entry, which is entirely attacker-controlled.
 */
export function configureTrustProxy(app: Express): void {
  const raw = process.env.TRUST_PROXY;
  const isProd = process.env.NODE_ENV === "production";

  let value: number | boolean | string[];
  if (raw === undefined || raw === "") {
    value = isProd ? 1 : 0;
  } else if (raw === "true") {
    value = true;
  } else if (raw === "false") {
    value = false;
  } else if (/^\d+$/.test(raw)) {
    value = Number(raw);
  } else {
    value = raw.split(",").map((s) => s.trim()).filter(Boolean);
  }

  app.set("trust proxy", value);

  if (value === true) {
    logger.warn(
      "TRUST_PROXY=true trusts the leftmost X-Forwarded-For entry, which clients control — " +
        "rate limits can be bypassed. Prefer a hop count.",
    );
  }
  logger.info({ trustProxy: value }, "Proxy trust configured");
}

/** The caller's address, as resolved by Express under the configured trust. */
export function clientIp(req: Request): string {
  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

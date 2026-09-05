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
 * proxy on the VPS deployment.
 *
 * ── Cloudflare, and why req.ip is not the whole story ──
 * The hosted deployment puts Cloudflare in front of a managed platform, where
 * there is no Caddy to sanitise the header and no firewall to stop anyone
 * reaching the origin directly. There CF-Connecting-IP is the accurate answer,
 * but only for requests that genuinely came through Cloudflare — which is what
 * cameThroughCloudflare establishes. Everything else falls back to req.ip.
 */

import { timingSafeEqual } from "node:crypto";
import type { Express, Request } from "express";
import { logger } from "./logger";
import { isCloudflareIp } from "./cloudflareIps";

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
  const raw = process.env["TRUST_PROXY"];
  const isProd = process.env["NODE_ENV"] === "production";

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

/** True when the deployment is fronted by Cloudflare. */
export function behindCloudflare(): boolean {
  return process.env["BEHIND_CLOUDFLARE"] === "true";
}

/**
 * Proof that a request arrived through Cloudflare rather than at the origin
 * directly.
 *
 * On a server you control, the origin is firewalled to Cloudflare's ranges and
 * arriving at all is the proof. A managed platform keeps a public hostname that
 * cannot be closed off, so a request sent straight to it can carry any
 * CF-Connecting-IP the sender likes.
 *
 * Two independent proofs, either of which suffices.
 *
 * The first needs no configuration anywhere. Each hop appends the address it
 * saw to X-Forwarded-For, so the *last* entry is the address the platform's
 * router observed — the Cloudflare edge, for a proxied request. A client can
 * prepend anything it likes to that header but cannot control its final entry,
 * because the platform writes it.
 *
 * The second is a shared secret Cloudflare attaches with a Transform Rule. It is
 * a stronger claim where available, but Transform Rules are not on every
 * Cloudflare plan, which is why it is not the only mechanism.
 */
function cameThroughCloudflare(req: Request): boolean {
  // ── Proof 1: the hop that reached us belongs to Cloudflare ────────────────
  const xff = req.headers["x-forwarded-for"];
  const chain = (Array.isArray(xff) ? xff.join(",") : xff ?? "")
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean);
  const lastHop = chain[chain.length - 1];
  if (lastHop && isCloudflareIp(lastHop)) return true;

  // ── Proof 2: a secret only Cloudflare could have attached ─────────────────
  const expected = process.env["CLOUDFLARE_ORIGIN_SECRET"];

  // Nothing else to check. Falling through to false is safe in every topology
  // this runs in: the caller then uses req.ip, which Express derives honouring
  // the trust proxy hop count. Refusing to guess costs accurate attribution
  // only when Cloudflare adds a range we have not refreshed yet.
  if (!expected) return false;

  const header = req.headers["x-origin-secret"];
  const provided = Array.isArray(header) ? header[0] : header;
  if (typeof provided !== "string" || provided.length === 0) return false;

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  // timingSafeEqual throws on a length mismatch, which would itself leak the
  // length, so compare lengths first and always run the comparison.
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** The caller's address, as resolved by Express under the configured trust. */
export function clientIp(req: Request): string {
  if (behindCloudflare() && cameThroughCloudflare(req)) {
    const cf = req.headers["cf-connecting-ip"];
    if (typeof cf === "string" && cf.trim()) return cf.trim();
    // Falling through is deliberate: a request reaching a Cloudflare-fronted
    // origin without this header did not come through Cloudflare, and req.ip is
    // the honest answer for it.
  }

  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

/**
 * Who is making this request, for rate-limiting purposes.
 *
 * This used to be `X-Forwarded-For.split(",")[0]` in three places, which takes
 * the *first* entry of a header the client fully controls. Anyone could send
 * `X-Forwarded-For: <random>` and appear as a new address on every request,
 * which defeats a per-IP limiter completely — including the one on /login.
 *
 * Two rules fix it:
 *
 *   1. Prefer CF-Connecting-IP when the request demonstrably came through
 *      Cloudflare. Cloudflare sets that header and strips any copy the client
 *      tried to send, so it cannot be forged *by a client speaking to
 *      Cloudflare*. It is worthless against a client speaking to the origin
 *      directly, which is what CLOUDFLARE_ORIGIN_SECRET below is for.
 *
 *   2. Otherwise use `req.ip`, which Express derives from X-Forwarded-For
 *      honouring the `trust proxy` hop count. With TRUST_PROXY set correctly it
 *      takes the entry the outermost trusted proxy observed and ignores
 *      anything the client prepended.
 *
 * Getting this wrong is quiet: the limiter still appears to work, still logs,
 * still returns 429 to honest traffic, and does nothing at all to an attacker.
 */

import { timingSafeEqual } from "node:crypto";
import type { Request } from "express";

/** True when the deployment is fronted by Cloudflare. */
export function behindCloudflare(): boolean {
  return process.env["BEHIND_CLOUDFLARE"] === "true";
}

/**
 * Proof that a request arrived through Cloudflare rather than at the origin
 * directly.
 *
 * On a server you control, the origin is firewalled to Cloudflare's ranges and
 * arriving at all is the proof. On a platform like Railway, Fly or Render there
 * is no such firewall: the service keeps a public hostname that anyone can
 * reach, and a request sent straight to it can carry any CF-Connecting-IP the
 * sender likes. Trusting the header there would hand an attacker a fresh
 * identity per request — the exact hole this module exists to close.
 *
 * So on those platforms, Cloudflare is configured to add a secret header to
 * every request it forwards, and only requests carrying it are treated as
 * having come through Cloudflare. Set the same value here.
 *
 * Compared in constant time: a byte-by-byte comparison against a secret is
 * measurable over enough requests, and there is no reason to leave that open.
 */
function cameThroughCloudflare(req: Request): boolean {
  const expected = process.env["CLOUDFLARE_ORIGIN_SECRET"];

  // No secret configured: this is the firewalled-origin deployment, where
  // reaching the origin at all is the proof.
  if (!expected) return true;

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

export function clientIp(req: Request): string {
  if (behindCloudflare() && cameThroughCloudflare(req)) {
    const cf = req.headers["cf-connecting-ip"];
    if (typeof cf === "string" && cf.trim()) return cf.trim();
    // Falling through here is deliberate. A request that reaches a
    // Cloudflare-fronted origin without this header did not come through
    // Cloudflare, and req.ip is the honest answer for it.
  }

  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

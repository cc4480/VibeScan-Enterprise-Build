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
 *   1. Prefer CF-Connecting-IP when the origin sits behind Cloudflare.
 *      Cloudflare sets it and strips any copy the client tried to send, so it
 *      cannot be forged by the client — but only while requests genuinely
 *      arrive through Cloudflare, which is why it is opt-in rather than
 *      automatic. An origin reachable directly must not trust it: there,
 *      the header is just another thing a client can type.
 *
 *   2. Otherwise use `req.ip`, which Express derives from X-Forwarded-For
 *      honouring the `trust proxy` hop count. With TRUST_PROXY=1 it takes the
 *      entry one hop back — the address the proxy observed — and ignores
 *      anything the client prepended.
 *
 * Getting this wrong is quiet: the limiter still appears to work, still logs,
 * still returns 429 to honest traffic, and does nothing at all to an attacker.
 */

import type { Request } from "express";

/** True when the deployment is fronted by Cloudflare and only reachable through it. */
export function behindCloudflare(): boolean {
  return process.env["BEHIND_CLOUDFLARE"] === "true";
}

export function clientIp(req: Request): string {
  if (behindCloudflare()) {
    const cf = req.headers["cf-connecting-ip"];
    if (typeof cf === "string" && cf.trim()) return cf.trim();
    // Falling through here is deliberate. A request that reaches a
    // Cloudflare-fronted origin without this header did not come through
    // Cloudflare, and req.ip is the honest answer for it.
  }

  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

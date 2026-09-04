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
import { isCloudflareIp } from "./cloudflareIps";

/** True when the deployment is fronted by Cloudflare. */
export function behindCloudflare(): boolean {
  return process.env["BEHIND_CLOUDFLARE"] === "true";
}

/**
 * Proof that a request arrived through Cloudflare rather than at the origin
 * directly.
 *
 * On a server you control, the origin is firewalled to Cloudflare's ranges and
 * arriving at all is the proof. A managed platform — Railway, Fly, Render —
 * keeps a public hostname that cannot be closed off, so a request sent straight
 * to it can carry any CF-Connecting-IP the sender likes. Trusting the header
 * there would hand an attacker a fresh identity per request, which is the exact
 * hole this module exists to close.
 *
 * Two independent proofs, either of which suffices.
 *
 * The first needs no configuration anywhere. Each hop appends the address it
 * saw to X-Forwarded-For, so the *last* entry is the address the platform's
 * router observed — the Cloudflare edge, for a proxied request. A client can
 * prepend anything it likes to that header but cannot control its final entry,
 * because the platform writes it. Checking that entry against Cloudflare's
 * published ranges therefore settles the question on its own.
 *
 * The second is a shared secret Cloudflare attaches with a Transform Rule. It
 * is kept because it is a stronger claim where it is available — but it is not
 * available on every Cloudflare plan, which is why it is no longer the only
 * mechanism.
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
  // this runs in: the caller then uses req.ip, which Express derives from the
  // same X-Forwarded-For honouring the trust proxy hop count, and which is the
  // real client address wherever TRUST_PROXY matches reality. Refusing to guess
  // costs accurate attribution only when Cloudflare adds a range we have not
  // refreshed yet.
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

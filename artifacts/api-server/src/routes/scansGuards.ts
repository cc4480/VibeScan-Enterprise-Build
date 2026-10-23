/** Rate limits and the auth guard in front of POST /api/scans. */
import { type Request, type Response, type NextFunction } from "express";
import { rateLimitMiddleware, scanRateLimitRules, scanNetworkRateLimitRules } from "../lib/rateLimit";

// Per USER, not per IP. This limit used to bucket on the client address, which
// meant every customer behind one office NAT, VPN or campus egress shared a
// single 5-scans-per-hour allowance: the second colleague to launch a scan was
// refused because of what the first one did, with an error blaming them for it.
export const scanRateLimit = rateLimitMiddleware({
  rules: scanRateLimitRules(),
  name: "scans",
  // Only reached after requireScanAuth below, so the user is always present.
  keyFrom: (req) => (req.isAuthenticated() ? `user:${req.user.id}` : undefined),
});

// Per NETWORK, above the per-user cap. The per-user gate cannot see one host
// creating accounts to multiply its allowance; this can.
export const scanNetworkRateLimit = rateLimitMiddleware({
  rules: scanNetworkRateLimitRules(),
  name: "scans-network",
});

// Authentication runs BEFORE the limiters, which is a fix in its own right:
// with the limiter first, unauthenticated requests consumed the bucket, so
// anyone could spend a signed-in user's scan allowance — or, once keyed per
// user, would have had no identity to bucket on at all.
export function requireScanAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.isAuthenticated()) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

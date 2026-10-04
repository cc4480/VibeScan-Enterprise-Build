/**
 * The per-account scan caps that "unlimited" is subject to, for the pricing to show beside the claim.
 *
 * SecScan Unlimited does not count scans, but the per-account rate limits in rateLimit.ts still
 * apply to it (5 an hour and 20 a day by default, tunable with SCAN_LIMIT_PER_HOUR and
 * SCAN_LIMIT_PER_DAY). A limit that material belongs next to the word "unlimited", not only in
 * the Terms, so the catalog and the payments-live email read the live values from here rather
 * than a copy that could drift from what the limiter enforces.
 */
import { scanRateLimitRules } from "./rateLimit";

export interface ScanLimits {
  perHour: number;
  perDay: number;
}

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** The caps the scan limiter enforces per account, read from its own rules. */
export function scanLimitsForPricing(): ScanLimits {
  const rules = scanRateLimitRules();
  const max = (windowMs: number) => rules.find((r) => r.windowMs === windowMs)?.max ?? 0;
  return { perHour: max(HOUR_MS), perDay: max(DAY_MS) };
}

/** "fair use: up to 5 scans an hour and 20 a day", for beside "unlimited". */
export function fairUseText(limits: ScanLimits = scanLimitsForPricing()): string {
  return `fair use: up to ${limits.perHour} scans an hour and ${limits.perDay} a day`;
}

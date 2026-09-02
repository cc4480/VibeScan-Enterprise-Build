/**
 * Sliding-window rate limiting, keyed by client address.
 *
 * Scans are expensive in a way most endpoints are not: a deep scan issues
 * 300–500+ outbound requests and, when a DeepSeek key is configured, bills an
 * AI call. Unlimited anonymous scan creation means anyone can aim this
 * deployment's outbound traffic at a third party or run up the API bill, so
 * POST /scans and monitor-subscription creation are limited.
 *
 * State is in-process. That is the right fit for the shipped single-container
 * compose stack and keeps a Redis out of the deployment; the tradeoffs are that
 * counters reset on restart and each replica limits independently, so running
 * more than one app container needs shared storage instead.
 */

import type { Request, Response, NextFunction } from "express";
import { clientIp } from "./clientIp";
import { logger } from "./logger";

export interface RateLimitRule {
  /** Window length in milliseconds. */
  windowMs: number;
  /** Requests permitted per window. */
  max: number;
  /** Shown to the caller when this rule is the one that trips. */
  label: string;
}

interface Bucket {
  /** Timestamps of counted hits, ascending. */
  hits: number[];
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/**
 * Default scan limits. Generous enough that a person evaluating the product
 * never notices, tight enough that the deployment cannot be used as an attack
 * relay. Tune with SCAN_LIMIT_PER_HOUR / SCAN_LIMIT_PER_DAY.
 */
export function scanRateLimitRules(): RateLimitRule[] {
  return [
    {
      windowMs: HOUR_MS,
      max: parsePositiveInt(process.env.SCAN_LIMIT_PER_HOUR, 5),
      label: "hour",
    },
    {
      windowMs: DAY_MS,
      max: parsePositiveInt(process.env.SCAN_LIMIT_PER_DAY, 20),
      label: "day",
    },
  ];
}

export interface RateLimiterOptions {
  rules: RateLimitRule[];
  /** Distinguishes buckets between endpoints sharing this module. */
  name: string;
}

export interface RateLimitDecision {
  allowed: boolean;
  /** Seconds until the caller may retry; only set when blocked. */
  retryAfterSeconds?: number;
  /** The rule that blocked, for the message. */
  rule?: RateLimitRule;
}

/**
 * The limiter's decision logic, separated from Express so it can be tested
 * directly and reused by non-HTTP callers.
 */
export class SlidingWindowLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly rules: RateLimitRule[];
  private readonly longestWindowMs: number;

  constructor(rules: RateLimitRule[]) {
    if (rules.length === 0) throw new Error("SlidingWindowLimiter needs at least one rule");
    this.rules = rules;
    this.longestWindowMs = Math.max(...rules.map((r) => r.windowMs));
  }

  /**
   * Record a hit for `key` and say whether it is permitted.
   *
   * A blocked request is NOT counted. Counting it would let a caller who keeps
   * hammering a blocked endpoint push their own retry time further and further
   * out, turning a rate limit into an ever-growing ban.
   */
  check(key: string, now: number = Date.now()): RateLimitDecision {
    const bucket = this.buckets.get(key) ?? { hits: [] };

    // One prune against the longest window serves every rule; shorter rules
    // filter further below.
    const cutoff = now - this.longestWindowMs;
    bucket.hits = bucket.hits.filter((t) => t > cutoff);

    for (const rule of this.rules) {
      const windowStart = now - rule.windowMs;
      const inWindow = bucket.hits.filter((t) => t > windowStart);
      if (inWindow.length >= rule.max) {
        // Capacity frees up when the oldest hit in this window ages out.
        const oldest = inWindow[0]!;
        const retryAfterSeconds = Math.max(1, Math.ceil((oldest + rule.windowMs - now) / 1000));
        this.buckets.set(key, bucket);
        return { allowed: false, retryAfterSeconds, rule };
      }
    }

    bucket.hits.push(now);
    this.buckets.set(key, bucket);
    return { allowed: true };
  }

  /** Drop buckets with nothing left in the longest window. */
  prune(now: number = Date.now()): void {
    const cutoff = now - this.longestWindowMs;
    for (const [key, bucket] of this.buckets) {
      if (bucket.hits.every((t) => t <= cutoff)) this.buckets.delete(key);
    }
  }

  /** Bucket count — for tests and diagnostics. */
  size(): number {
    return this.buckets.size;
  }
}

/**
 * Express middleware wrapper. Sweeps idle buckets periodically so a long-running
 * process does not accumulate one entry per address seen since boot.
 */
export function rateLimitMiddleware(options: RateLimiterOptions) {
  const limiter = new SlidingWindowLimiter(options.rules);

  const sweep = setInterval(() => limiter.prune(), HOUR_MS);
  // Do not hold the event loop open on shutdown.
  sweep.unref?.();

  return function rateLimit(req: Request, res: Response, next: NextFunction): void {
    const key = clientIp(req);
    const decision = limiter.check(key);

    if (decision.allowed) {
      next();
      return;
    }

    res.setHeader("Retry-After", String(decision.retryAfterSeconds ?? 60));
    logger.warn(
      { ip: key, limiter: options.name, rule: decision.rule?.label },
      "Rate limit exceeded",
    );
    res.status(429).json({
      error:
        `Rate limit reached — at most ${decision.rule?.max} per ${decision.rule?.label}. ` +
        `Try again in ${decision.retryAfterSeconds} seconds.`,
    });
  };
}

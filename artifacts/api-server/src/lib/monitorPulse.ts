/**
 * The hourly pulse check.
 *
 * Monitoring had a gap between rescans. The adaptive cadence is measured in
 * days because a full scan is minutes of work, several paid API calls and real
 * traffic at somebody's site — so a healthy site is scanned every fourteen days
 * and the dashboard had nothing at all to say for the other thirteen. A site
 * could go down, lose its HSTS header, or start redirecting to a domain its
 * owner has never heard of, and the product would keep showing a grade from a
 * fortnight ago with no sign anyone had looked since.
 *
 * A pulse is one HTTP request and one TLS handshake. It cannot grade a site and
 * does not try. It answers three questions — is it up, is the certificate still
 * valid, has anything visible changed — and it guarantees the dashboard a
 * last-checked time that is never more than an hour old.
 *
 * Everything that decides whether to wake somebody up is a pure function in
 * this file, tested without a network or a database, because the failure modes
 * are silent in both directions: too eager and it is the alert people mute,
 * too quiet and the outage goes unreported.
 */

import { logger } from "./logger";
import { SCANNER_USER_AGENT } from "./http";
import { readBodyBounded } from "./httpBody";
import { scanDispatcher } from "./pinnedDispatcher";
import { checkScanTarget } from "./ssrfGuard";
import { type HeaderSnapshot, snapshotHeaders } from "./monitorPulseHeaders";
import { PULSE_TIMEOUT_MS, probeCertDates } from "./monitorPulseCert";
export { TRACKED_HEADERS, hstsBucket, snapshotHeaders, evaluateDrift } from "./monitorPulseHeaders";
export { certDaysRemaining, probeCertExpiry, certAlertThresholds } from "./monitorPulseCert";
export type { TrackedHeader, HstsBucket, HeaderSnapshot, DriftFinding } from "./monitorPulseHeaders";

/** How long pulse rows are kept. They are a rolling window, not a record. */
export const PULSE_RETENTION_DAYS = 30;

/**
 * Consecutive failed pulses before a down alert fires.
 *
 * One is too eager: a single dropped request at 03:00 is not an outage, and an
 * alert that cries wolf hourly is the alert people turn off — taking the real
 * outage with it. Two consecutive hourly checks means a site has been
 * unreachable for about an hour before anyone is woken, which is the right
 * trade for a security product rather than an uptime pager.
 */
export const DOWN_THRESHOLD = 2;

// ── Availability ──────────────────────────────────────────────────────────────

export type AvailabilityEvent = "down" | "recovered" | null;

/**
 * Whether this pulse changes what the user should be told about availability.
 *
 * `earlierPulses` is newest-first and does NOT include the current pulse.
 *
 * Fires at most once per outage in each direction:
 *   - "down" only on the pulse that makes the run of failures exactly
 *     DOWN_THRESHOLD long, so a four-hour outage sends one email, not four.
 *   - "recovered" only if the outage had reached that threshold, so a blip that
 *     was never reported is never "resolved" either.
 *
 * Counted in pulses, not hours. If the worker was down for six hours the gap
 * simply is not in the table, and a site that was unreachable either side of it
 * reads as two consecutive failures — which is the honest reading of what we
 * actually observed.
 */
export function evaluateAvailability(
  earlierPulses: Array<{ reachable: boolean }>,
  current: { reachable: boolean },
): AvailabilityEvent {
  let priorFailures = 0;
  for (const pulse of earlierPulses) {
    if (pulse.reachable) break;
    priorFailures++;
  }

  if (!current.reachable) {
    return priorFailures + 1 === DOWN_THRESHOLD ? "down" : null;
  }

  return priorFailures >= DOWN_THRESHOLD ? "recovered" : null;
}

// ── Uptime summary ────────────────────────────────────────────────────────────

export interface UptimeSummary {
  /** Percentage of pulses in the window that reached the site, or null if none. */
  uptimePct: number | null;
  /** Median response time of the successful pulses, or null. */
  medianResponseMs: number | null;
  checks: number;
}

/**
 * Median rather than mean: one 8-second timeout should not make a site that
 * normally answers in 200ms look slow all day.
 */
export function summariseUptime(
  pulses: Array<{ reachable: boolean; responseTimeMs: number | null }>,
): UptimeSummary {
  if (pulses.length === 0) return { uptimePct: null, medianResponseMs: null, checks: 0 };

  const up = pulses.filter((p) => p.reachable).length;
  const times = pulses
    .filter((p) => p.reachable && p.responseTimeMs != null)
    .map((p) => p.responseTimeMs as number)
    .sort((a, b) => a - b);

  let median: number | null = null;
  if (times.length > 0) {
    const mid = Math.floor(times.length / 2);
    median =
      times.length % 2 === 0
        ? Math.round((times[mid - 1] + times[mid]) / 2)
        : times[mid];
  }

  return {
    uptimePct: Math.round((up / pulses.length) * 1000) / 10,
    medianResponseMs: median,
    checks: pulses.length,
  };
}

export interface PulseResult {
  reachable: boolean;
  httpStatus: number | null;
  responseTimeMs: number | null;
  finalUrl: string;
  snapshot: HeaderSnapshot | null;
  certExpiresAt: Date | null;
  /** The certificate's notBefore. Not stored; used to tell auto-renewing certificates apart. */
  certIssuedAt?: Date | null;
  failureReason: string | null;
}

/**
 * How many redirects a pulse will follow before giving up.
 *
 * Each hop is checked against the SSRF guard before it is requested, so this is
 * a cost limit rather than a safety one — but a site redirecting more than five
 * times is misconfigured, and a redirect loop must not hold a worker slot.
 */
const MAX_REDIRECTS = 5;

/**
 * One pulse: a GET, its headers, and the certificate.
 *
 * GET rather than HEAD because a meaningful minority of sites answer HEAD with
 * 405 or omit headers from it, and a check that reports a healthy site as
 * broken is worse than one extra request an hour. The body is discarded
 * unread.
 *
 * Redirects are followed BY HAND, with every hop checked against the SSRF guard
 * first. `redirect: "follow"` would have undone the check done when the
 * subscription was created: a target validated as public a month ago can answer
 * today with a 302 to 169.254.169.254, and fetch would follow it before
 * anything got a chance to look. This is the same reason webhook.ts uses
 * `redirect: "error"` — it just cannot refuse redirects outright, because
 * plenty of monitored URLs legitimately redirect to www or to HTTPS.
 *
 * Never throws — an unreachable site is a result, not an error.
 */
export async function runPulse(targetUrl: string): Promise<PulseResult> {
  const startedAt = Date.now();

  try {
    let currentUrl = targetUrl;
    let res: Response | null = null;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      // checkScanTarget, not a stricter check of our own: it is the same gate
      // the subscription passed when it was created, and the same one the
      // scanner uses. A self-hosted operator who deliberately points SecScan at
      // their own network must not find that scans work and hourly checks
      // report "blocked" every hour.
      const { ok: safe, reason } = await checkScanTarget(currentUrl);
      if (!safe) {
        // Deliberately reported as a failed check rather than swallowed. A
        // monitored site that starts redirecting somewhere it should not is
        // exactly the kind of change the user is paying us to notice.
        logger.warn({ targetUrl, hop }, "Pulse blocked by SSRF guard");
        return {
          reachable: false,
          httpStatus: null,
          responseTimeMs: Date.now() - startedAt,
          finalUrl: currentUrl,
          snapshot: null,
          certExpiresAt: null,
          failureReason: `Blocked: ${reason ?? "unsafe redirect target"}`,
        };
      }

      res = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        headers: { "User-Agent": SCANNER_USER_AGENT, Accept: "*/*" },
        signal: AbortSignal.timeout(PULSE_TIMEOUT_MS),
        // Same connect-time pinning as the scanner, and the same self-host opt-in as the check above.
        dispatcher: scanDispatcher,
      } as RequestInit);

      const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
      if (!location) break;

      // Capped like every other scanner body read: a redirect body is discarded, but not without a bound.
      void readBodyBounded(res).catch(() => undefined);
      // Resolved against the current URL, so a relative Location works.
      currentUrl = new URL(location, currentUrl).toString();
      res = null;
    }

    if (!res) {
      return {
        reachable: false,
        httpStatus: null,
        responseTimeMs: Date.now() - startedAt,
        finalUrl: currentUrl,
        snapshot: null,
        certExpiresAt: null,
        failureReason: `More than ${MAX_REDIRECTS} redirects`,
      };
    }

    const responseTimeMs = Date.now() - startedAt;
    // Drain rather than leave the socket half-read, bounded like every other body read.
    void readBodyBounded(res).catch(() => undefined);

    const cert = await probeCertDates(currentUrl);

    return {
      // A 404 means the server is answering; a 500 or 503 means it is not
      // serving the site. Availability here is "does the site respond", not
      // "does this exact path exist".
      reachable: res.status < 500,
      httpStatus: res.status,
      responseTimeMs,
      finalUrl: currentUrl,
      snapshot: snapshotHeaders(res.headers),
      certExpiresAt: cert?.expiresAt ?? null,
      certIssuedAt: cert?.issuedAt ?? null,
      failureReason: res.status >= 500 ? `HTTP ${res.status}` : null,
    };
  } catch (err) {
    const responseTimeMs = Date.now() - startedAt;
    const reason =
      err instanceof Error
        ? err.name === "TimeoutError" || err.name === "AbortError"
          ? `No response within ${PULSE_TIMEOUT_MS / 1000}s`
          : err.message.slice(0, 200)
        : "Request failed";

    logger.debug({ targetUrl, reason }, "Pulse check failed");

    return {
      reachable: false,
      httpStatus: null,
      responseTimeMs,
      finalUrl: targetUrl,
      snapshot: null,
      certExpiresAt: null,
      failureReason: reason,
    };
  }
}
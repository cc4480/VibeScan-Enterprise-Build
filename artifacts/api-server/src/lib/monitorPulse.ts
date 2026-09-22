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
import { createHash } from "node:crypto";
import * as tls from "node:tls";
import { logger } from "./logger";
import { SCANNER_USER_AGENT } from "./http";
import { checkScanTarget } from "./ssrfGuard";
import type { Severity } from "./notificationPrefs";

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

/**
 * Headers whose disappearance is a real change in a site's security posture.
 *
 * PRESENCE is fingerprinted, not values. A Content-Security-Policy containing a
 * per-response nonce changes on every single request, so hashing values would
 * report drift every hour on exactly the sites doing CSP properly. The one
 * value that is tracked is HSTS max-age, because a header that is still present
 * with max-age=0 has been switched off while looking untouched.
 */
export const TRACKED_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
] as const;

export type TrackedHeader = (typeof TRACKED_HEADERS)[number];

/** Coarse buckets, so a site raising max-age from one year to two is not "drift". */
export type HstsBucket = "none" | "short" | "ok";

const ONE_WEEK_SECONDS = 7 * 24 * 60 * 60;

export function hstsBucket(headerValue: string | null | undefined): HstsBucket {
  if (!headerValue) return "none";
  const match = /max-age\s*=\s*"?(\d+)"?/i.exec(headerValue);
  if (!match) return "none";
  const maxAge = parseInt(match[1], 10);
  if (!Number.isFinite(maxAge) || maxAge <= 0) return "none";
  return maxAge < ONE_WEEK_SECONDS ? "short" : "ok";
}

export interface HeaderSnapshot {
  /** Tracked headers that were present, lowercased and sorted. */
  present: TrackedHeader[];
  hsts: HstsBucket;
  /** Stable hash of the two fields above. */
  fingerprint: string;
}

/**
 * Reduce a response's headers to the part worth comparing hour to hour.
 *
 * Accepts either a Headers object or a plain record so tests need no fetch.
 */
export function snapshotHeaders(
  headers: Headers | Record<string, string | null | undefined>,
): HeaderSnapshot {
  const read = (name: string): string | null => {
    if (typeof (headers as Headers).get === "function") {
      return (headers as Headers).get(name);
    }
    const record = headers as Record<string, string | null | undefined>;
    // A plain record may be cased however the caller wrote it.
    const hit = Object.keys(record).find((k) => k.toLowerCase() === name);
    return hit ? record[hit] ?? null : null;
  };

  const present = TRACKED_HEADERS.filter((name) => {
    const value = read(name);
    return value != null && value !== "";
  });

  const hsts = hstsBucket(read("strict-transport-security"));

  const fingerprint = createHash("sha256")
    .update(`${[...present].sort().join(",")}|hsts=${hsts}`)
    .digest("hex")
    .slice(0, 32);

  return { present: [...present], hsts, fingerprint };
}

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

// ── Drift ─────────────────────────────────────────────────────────────────────

export interface DriftFinding {
  kind: "header_removed" | "hsts_weakened" | "final_url_changed" | "tls_downgrade";
  detail: string;
  severity: Severity;
}

/**
 * What changed since the last pulse that reached the site.
 *
 * Only changes that WEAKEN the site are reported. A header appearing is good
 * news and not an alert; a header vanishing is. Compared against the previous
 * successful pulse rather than simply the previous one, so an outage does not
 * produce a spurious "everything disappeared" the hour it starts and a
 * spurious "everything came back" the hour it ends.
 */
export function evaluateDrift(
  previous: {
    headerFingerprint: string | null;
    presentHeaders: string[] | null;
    finalUrl: string | null;
  } | null,
  current: { snapshot: HeaderSnapshot; finalUrl: string },
  previousHsts?: HstsBucket,
): DriftFinding[] {
  if (!previous) return [];
  if (previous.headerFingerprint === current.snapshot.fingerprint) return [];

  const findings: DriftFinding[] = [];

  const before = new Set(previous.presentHeaders ?? []);
  for (const name of before) {
    if (!current.snapshot.present.includes(name as TrackedHeader)) {
      findings.push({
        kind: "header_removed",
        detail: name,
        // Losing a security header is a posture change worth a mail, but it is
        // not an exploited vulnerability. "medium" keeps it above a raised
        // floor of low and below one of high.
        severity: "medium",
      });
    }
  }

  if (previousHsts === "ok" && current.snapshot.hsts !== "ok") {
    findings.push({
      kind: "hsts_weakened",
      detail:
        current.snapshot.hsts === "none"
          ? "Strict-Transport-Security no longer enforces HSTS (max-age is 0 or missing)"
          : "Strict-Transport-Security max-age dropped below one week",
      severity: "high",
    });
  }

  if (previous.finalUrl && previous.finalUrl !== current.finalUrl) {
    const beforeUrl = safeUrl(previous.finalUrl);
    const afterUrl = safeUrl(current.finalUrl);

    if (beforeUrl?.protocol === "https:" && afterUrl?.protocol === "http:") {
      findings.push({
        kind: "tls_downgrade",
        detail: `${previous.finalUrl} now resolves over plain HTTP`,
        severity: "critical",
      });
    } else if (beforeUrl && afterUrl && beforeUrl.host !== afterUrl.host) {
      // A different host at the end of the redirect chain is the shape of a
      // hijacked domain or a misdirected DNS record, so it outranks a header.
      findings.push({
        kind: "final_url_changed",
        detail: `Now redirects to ${afterUrl.host} (was ${beforeUrl.host})`,
        severity: "high",
      });
    }
    // A path-only change on the same host is routine and deliberately silent.
  }

  return findings;
}

function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
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

// ── Certificate expiry ────────────────────────────────────────────────────────

export function certDaysRemaining(expiresAt: Date | null, now: Date = new Date()): number | null {
  if (!expiresAt) return null;
  if (Number.isNaN(expiresAt.getTime())) return null;
  return Math.ceil((expiresAt.getTime() - now.getTime()) / 86_400_000);
}

// ── The probe itself ──────────────────────────────────────────────────────────

const PULSE_TIMEOUT_MS = 10_000;

export interface PulseResult {
  reachable: boolean;
  httpStatus: number | null;
  responseTimeMs: number | null;
  finalUrl: string;
  snapshot: HeaderSnapshot | null;
  certExpiresAt: Date | null;
  failureReason: string | null;
}

/**
 * Probe the TLS certificate expiry for an https URL.
 *
 * rejectUnauthorized is false on purpose: an expired or self-signed
 * certificate is precisely what we are trying to report, and refusing the
 * handshake would turn the finding into a null.
 */
export async function probeCertExpiry(rawUrl: string): Promise<Date | null> {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:") return null;
    const host = url.hostname;
    const port = parseInt(url.port || "443", 10);

    return await new Promise<Date | null>((resolve) => {
      const socket = tls.connect(
        { host, port, servername: host, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          if (!cert || !cert.valid_to) {
            resolve(null);
            return;
          }
          const parsed = new Date(cert.valid_to);
          resolve(Number.isNaN(parsed.getTime()) ? null : parsed);
        },
      );
      socket.on("error", () => resolve(null));
      socket.setTimeout(PULSE_TIMEOUT_MS, () => {
        socket.destroy();
        resolve(null);
      });
    });
  } catch {
    return null;
  }
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
      });

      const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
      if (!location) break;

      void res.arrayBuffer().catch(() => undefined);
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
    // Drain rather than leave the socket half-read.
    void res.arrayBuffer().catch(() => undefined);

    const certExpiresAt = await probeCertExpiry(currentUrl);

    return {
      // A 404 means the server is answering; a 500 or 503 means it is not
      // serving the site. Availability here is "does the site respond", not
      // "does this exact path exist".
      reachable: res.status < 500,
      httpStatus: res.status,
      responseTimeMs,
      finalUrl: currentUrl,
      snapshot: snapshotHeaders(res.headers),
      certExpiresAt,
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

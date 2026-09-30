/** Security-header snapshots and drift detection between pulses. */
import { createHash } from "node:crypto";
import type { Severity } from "./notificationPrefs";

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

export const ONE_WEEK_SECONDS = 7 * 24 * 60 * 60;

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

export function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

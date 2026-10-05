/**
 * The legacy anonymous bearer: policy, sunset and usage log.
 *
 * Before registration existed an anonymous account was a row whose UUID was the
 * only credential (`Authorization: Bearer <user id>`). A user id is not a secret,
 * so this is weak authentication; it is still honoured only so pre-registration
 * users are not cut off (see middlewares/authMiddleware.ts, and routes/account*.ts
 * where registering promotes the same row in place).
 *
 * Closing it is a deployment decision, so it is controlled by two variables:
 *
 *   ALLOW_LEGACY_ANONYMOUS_BEARER=false   Closes it now. ALWAYS wins, whatever
 *                                         LEGACY_BEARER_SUNSET says.
 *   LEGACY_BEARER_SUNSET=2026-12-01       Closes it automatically from that
 *                                         moment. An ISO 8601 date or timestamp;
 *                                         without an offset it is read as UTC, so
 *                                         a bare date means the start of that day.
 *                                         Unset (or unparseable) = never.
 *
 * With neither set the path stays open, exactly as before.
 *
 * An unparseable LEGACY_BEARER_SUNSET is treated as unset (fail open), NOT as
 * "already sunset": a typo in a date must not lock out everyone who still depends
 * on this path. It is logged as an error once at startup so it does not go
 * unnoticed (logLegacyBearerStatus).
 */

import { logger } from "./logger";

export const LEGACY_BEARER_SUNSET_ENV = "LEGACY_BEARER_SUNSET";
export const LEGACY_BEARER_SWITCH_ENV = "ALLOW_LEGACY_ANONYMOUS_BEARER";

type Env = Record<string, string | undefined>;

export type SunsetSetting =
  | { state: "unset" }
  | { state: "invalid"; raw: string }
  | { state: "set"; at: Date };

const ISO =
  /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})?)?$/i;

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

/**
 * Strict on purpose. `Date.parse` is lenient to the point of being dangerous
 * here: "12" parses as the year 2001 and "2026-02-31" as 3 March, and a sunset
 * date that silently means something other than what was typed is worse than one
 * that is rejected. Only ISO 8601 date / date-time forms are accepted, and the
 * calendar fields must be real.
 */
export function parseSunset(raw: string | undefined): SunsetSetting {
  const trimmed = raw?.trim();
  if (!trimmed) return { state: "unset" };

  const m = ISO.exec(trimmed);
  if (!m) return { state: "invalid", raw: trimmed };

  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = m[4] === undefined ? 0 : Number(m[4]);
  const minute = m[5] === undefined ? 0 : Number(m[5]);
  const second = m[6] === undefined ? 0 : Number(m[6]);
  if (month < 1 || month > 12) return { state: "invalid", raw: trimmed };
  if (day < 1 || day > daysInMonth(year, month)) return { state: "invalid", raw: trimmed };
  if (hour > 23 || minute > 59 || second > 59) return { state: "invalid", raw: trimmed };

  // Without an offset the engine would read a date-time in the server's local
  // zone, so the result would depend on where it is deployed. Pin it to UTC.
  const base = trimmed.replace(" ", "T").toUpperCase();
  const normalised = m[7] !== undefined ? base : `${base}${m[4] === undefined ? "T00:00:00" : ""}Z`;
  const at = new Date(normalised);
  if (Number.isNaN(at.getTime())) return { state: "invalid", raw: trimmed };
  return { state: "set", at };
}

/** True only for an explicit `false` (any case, surrounding spaces ignored). */
function switchedOff(env: Env): boolean {
  return env[LEGACY_BEARER_SWITCH_ENV]?.trim().toLowerCase() === "false";
}

/**
 * Is the legacy anonymous bearer accepted right now?
 *
 * Pure: the environment and the clock are parameters, so every branch is tested
 * without touching `process.env` or fake timers.
 *
 *   ALLOW_LEGACY_ANONYMOUS_BEARER=false  -> no (wins over everything)
 *   LEGACY_BEARER_SUNSET reached         -> no
 *   LEGACY_BEARER_SUNSET in the future   -> yes
 *   LEGACY_BEARER_SUNSET unset/invalid   -> yes (today's behaviour)
 */
export function legacyBearerAllowed(env: Env = process.env, now: Date = new Date()): boolean {
  if (switchedOff(env)) return false;
  const sunset = parseSunset(env[LEGACY_BEARER_SUNSET_ENV]);
  if (sunset.state === "set" && now.getTime() >= sunset.at.getTime()) return false;
  return true;
}

export interface StartupLog {
  info(obj: object, msg: string): void;
  error(obj: object, msg: string): void;
}

/**
 * Startup line saying where the cutover stands, so an operator reading the boot
 * log does not have to work it out from the environment. An unparseable sunset
 * is an error, once, because it is otherwise silent: the path just stays open.
 */
export function logLegacyBearerStatus(log: StartupLog, env: Env = process.env, now: Date = new Date()): void {
  const sunset = parseSunset(env[LEGACY_BEARER_SUNSET_ENV]);
  if (sunset.state === "invalid") {
    log.error(
      { variable: LEGACY_BEARER_SUNSET_ENV, value: sunset.raw.slice(0, 64) },
      `${LEGACY_BEARER_SUNSET_ENV} is not an ISO 8601 date (for example 2026-12-01) and is being ignored: ` +
        "the legacy anonymous bearer will NOT be sunset until it is fixed",
    );
  }
  const allowed = legacyBearerAllowed(env, now);
  log.info(
    {
      legacyBearer: allowed ? "open" : "closed",
      closedBy: allowed ? undefined : switchedOff(env) ? LEGACY_BEARER_SWITCH_ENV : LEGACY_BEARER_SUNSET_ENV,
      sunset: sunset.state === "set" ? sunset.at.toISOString() : undefined,
    },
    "Legacy anonymous bearer authentication status",
  );
}

// ── Usage log ────────────────────────────────────────────────────────────────

const DAY_MS = 24 * 60 * 60_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The path as it should appear in a log. Share and out-of-band links carry a
 * bearer credential for one report in the URL, and the first request a legacy
 * user makes in a day could well be one, so those segments (and any other long
 * opaque one) are replaced rather than written to disk. Query strings are never
 * included.
 */
export function loggableRoute(method: string | undefined, path: string | undefined): string {
  const masked = (path ?? "")
    .split("?")[0]!
    .replace(/(\/(?:shares?|oob)\/)[^/]+/gi, "$1:token")
    // Ids are UUIDs and stay readable; anything else that long is opaque.
    .replace(/\/([A-Za-z0-9_-]{32,})(?=\/|$)/g, (whole, seg: string) => (UUID.test(seg) ? whole : "/:token"));
  return `${method ?? "?"} ${masked.slice(0, 200)}`;
}

export interface LegacyBearerLog {
  warn(obj: object, msg: string): void;
}

export interface LegacyBearerReporter {
  /**
   * Record that `userId` was authenticated through the legacy bearer on `route`.
   * Logs at most once per user id per window; returns whether it logged.
   */
  report(userId: string, route: string): boolean;
  /** Distinct user ids currently remembered. */
  size(): number;
  clear(): void;
}

export interface ReporterOptions {
  log: LegacyBearerLog;
  /** Injected clock, epoch milliseconds. */
  now?: () => number;
  /** Quiet period per user id. Default 24 hours. */
  windowMs?: number;
  /** Hard cap on remembered ids, so a flood of ids cannot grow memory. */
  maxEntries?: number;
}

/**
 * De-duplicating logger for legacy-bearer use.
 *
 * Every request from such a user would otherwise write a line, and the point of
 * the log is to answer "who still uses this?" — which one line a day per user
 * answers. State is an in-memory Map of user id to the time it was last logged:
 * per process, so each web replica logs once a day too, and a restart logs again,
 * which is the safe direction. Nothing secret is held or logged: the user id is
 * the only identifier (it is what the account is called in the database), the
 * route is masked by loggableRoute.
 */
export function createLegacyBearerReporter(opts: ReporterOptions): LegacyBearerReporter {
  const now = opts.now ?? Date.now;
  const windowMs = opts.windowMs ?? DAY_MS;
  const maxEntries = opts.maxEntries ?? 10_000;
  // Insertion order is last-logged order, because an id is deleted and re-set
  // each time it is logged. That makes pruning a walk from the front.
  const seen = new Map<string, number>();
  let lastPrune = now();

  function prune(at: number): void {
    for (const [id, loggedAt] of seen) {
      if (at - loggedAt < windowMs) break;
      seen.delete(id);
    }
    lastPrune = at;
  }

  return {
    report(userId, route) {
      const at = now();
      // Prune at most once a minute, not on every request.
      if (at - lastPrune >= 60_000 || seen.size >= maxEntries) prune(at);

      const previous = seen.get(userId);
      if (previous !== undefined && at - previous < windowMs) return false;

      // Re-set rather than overwrite, to keep the Map in last-logged order.
      seen.delete(userId);
      // Still full after dropping the expired: evict the oldest to stay bounded.
      // That id can be logged again early, which costs one line, not correctness.
      while (seen.size >= maxEntries) {
        const oldest = seen.keys().next().value;
        if (oldest === undefined) break;
        seen.delete(oldest);
      }
      seen.set(userId, at);
      opts.log.warn(
        { event: "legacy_anonymous_bearer", userId, route },
        "Request authenticated by legacy anonymous bearer (user id is the only credential). " +
          "Have this user register to keep their history, then close the path: " +
          `${LEGACY_BEARER_SUNSET_ENV} / ${LEGACY_BEARER_SWITCH_ENV}=false`,
      );
      return true;
    },
    size: () => seen.size,
    clear: () => {
      seen.clear();
      lastPrune = now();
    },
  };
}

/** The process-wide reporter the auth middleware uses. */
export const legacyBearerReporter: LegacyBearerReporter = createLegacyBearerReporter({
  // Resolved per call rather than captured, so a test that swaps the logger works.
  log: { warn: (obj, msg) => logger.warn(obj, msg) },
});

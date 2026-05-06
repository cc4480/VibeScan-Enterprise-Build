/**
 * EOL data fetcher — pulls end-of-life schedules from the endoflife.date API
 * and caches them in-process.
 *
 * Three products are fetched in parallel: PHP, Nginx, Apache HTTPD.
 *
 * Refresh cadence:
 *   • At server startup — non-blocking fire-and-forget (fast warm-up)
 *   • Daily at 03:00 UTC — pg-boss cron job (EOL_REFRESH_QUEUE)
 *
 * Failure handling:
 *   • Any fetch error is logged at WARN level — the bundled fallback tables
 *     remain active so scans are never blocked by upstream unavailability.
 *   • The cache is only updated after a fully successful fetch of all three
 *     products.  Partial results are discarded.
 *
 * Consumers:
 *   • cveCheck.ts — calls getLivePhpEol() / getLiveNginxEolCycles() /
 *     getLiveApacheEolCycles() at scan time instead of using hardcoded constants.
 *   • cveCheck.ts / warnIfLocalDataStale() — calls getEolDataFetchedAt() to
 *     report how fresh the active data is.
 */

import { logger } from "./logger";

// ─── pg-boss queue name (imported by worker.ts) ───────────────────────────────

export const EOL_REFRESH_QUEUE = "eol-refresh";

// ─── endoflife.date API response shape ───────────────────────────────────────

interface EolCycle {
  cycle: string;        // "8.3", "1.26", "2.4", …
  releaseDate: string;  // ISO date
  eol: string | false;  // ISO EOL date, or false when still actively supported
  latest: string;       // latest patch release in this cycle
  lts?: boolean;
  support?: string | false;
}

// ─── Bundled fallback data — mirrors the constants in cveCheck.ts ─────────────
//
// These are used as-is when the live fetch hasn't succeeded yet (e.g. first
// boot before the async refresh completes, or a network outage).

const FALLBACK_PHP_EOL: Record<string, string> = {
  "5":   "Reached EOL in December 2018",
  "7.0": "Reached EOL in December 2019",
  "7.1": "Reached EOL in December 2019",
  "7.2": "Reached EOL in November 2020",
  "7.3": "Reached EOL in December 2021",
  "7.4": "Reached EOL in November 2022",
  "8.0": "Reached EOL in November 2023",
  "8.1": "Reached EOL in December 2025",
  "8.2": "Reaches EOL in December 2026",
};

// Nginx stable cycles known to be EOL as of the bundled date (2026-05).
// The live fetch replaces this set entirely on success.
const FALLBACK_NGINX_EOL_CYCLES = new Set([
  "1.14", "1.15", "1.16", "1.17", "1.18", "1.19",
  "1.20", "1.21", "1.22", "1.23", "1.24", "1.25",
]);

// Apache HTTPD branches known to be EOL.
const FALLBACK_APACHE_EOL_CYCLES = new Set(["2.0", "2.2"]);

// ─── In-process cache ─────────────────────────────────────────────────────────

interface EolCache {
  phpEol: Record<string, string>;
  nginxEolCycles: Set<string>;
  apacheEolCycles: Set<string>;
  fetchedAt: Date;
}

let cache: EolCache | null = null;

// ─── Public getters ───────────────────────────────────────────────────────────

/** Returns the timestamp of the last successful EOL data refresh, or null. */
export function getEolDataFetchedAt(): Date | null {
  return cache?.fetchedAt ?? null;
}

/**
 * PHP EOL map keyed by "major.minor" (or "major" for PHP 5.x).
 * Returns live data when available, bundled fallback otherwise.
 */
export function getLivePhpEol(): Record<string, string> {
  return cache?.phpEol ?? FALLBACK_PHP_EOL;
}

/**
 * Set of Nginx release-cycle strings (e.g. "1.24", "1.25") that are EOL.
 * Returns live data when available, bundled fallback otherwise.
 */
export function getLiveNginxEolCycles(): Set<string> {
  return cache?.nginxEolCycles ?? FALLBACK_NGINX_EOL_CYCLES;
}

/**
 * Set of Apache HTTPD release-cycle strings (e.g. "2.2") that are EOL.
 * Returns live data when available, bundled fallback otherwise.
 */
export function getLiveApacheEolCycles(): Set<string> {
  return cache?.apacheEolCycles ?? FALLBACK_APACHE_EOL_CYCLES;
}

// ─── Fetch helpers ────────────────────────────────────────────────────────────

const EOL_API_TIMEOUT_MS = 10_000;
const EOL_API_BASE = "https://endoflife.date/api";

async function fetchEolCycles(product: string): Promise<EolCycle[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), EOL_API_TIMEOUT_MS);
  try {
    const res = await fetch(`${EOL_API_BASE}/${product}.json`, {
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "User-Agent": "VibeScan-SecurityScanner/1.0",
      },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} fetching endoflife.date/${product}`);
    return (await res.json()) as EolCycle[];
  } finally {
    clearTimeout(timer);
  }
}

// ─── Data builders ────────────────────────────────────────────────────────────

/**
 * Builds the PHP EOL map from live endoflife.date data.
 *
 * A PHP cycle is included when:
 *   - Its EOL date has passed       → "Reached EOL in <Month Year>"
 *   - Its EOL date is within 12 mo  → "Reaches EOL in <Month Year>"  (early warning)
 *   - Its EOL date is >12 mo away   → skipped (still comfortably supported)
 */
function buildPhpEolMap(cycles: EolCycle[]): Record<string, string> {
  const map: Record<string, string> = {};
  const now = new Date();
  const twelveMonthsOut = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  for (const c of cycles) {
    if (c.eol === false || !c.eol) continue; // still actively supported
    const eolDate = new Date(c.eol);
    const eolStr = eolDate.toLocaleDateString("en-US", { month: "long", year: "numeric" });

    if (eolDate <= now) {
      map[c.cycle] = `Reached EOL in ${eolStr}`;
    } else if (eolDate <= twelveMonthsOut) {
      map[c.cycle] = `Reaches EOL in ${eolStr}`;
    }
    // Cycles with EOL > 12 months away are omitted — actively supported
  }

  // PHP 5.x predates the endoflife.date dataset; ensure it is always included
  if (!map["5"]) map["5"] = FALLBACK_PHP_EOL["5"]!;

  return map;
}

/**
 * Builds a Set of EOL release-cycle strings for a server product (Nginx, Apache).
 * A cycle is EOL when its eol field is a date string ≤ today.
 */
function buildEolCycleSet(cycles: EolCycle[]): Set<string> {
  const now = new Date();
  const eol = new Set<string>();
  for (const c of cycles) {
    if (typeof c.eol === "string" && new Date(c.eol) <= now) {
      eol.add(c.cycle);
    }
  }
  return eol;
}

// ─── Main refresh function ────────────────────────────────────────────────────

/**
 * Fetches current EOL data for PHP, Nginx, and Apache from endoflife.date.
 * Updates the in-process cache on success; leaves it unchanged on any error.
 *
 * Called:
 *   - At startup (non-blocking void call from worker.ts)
 *   - Daily via pg-boss schedule (EOL_REFRESH_QUEUE)
 */
export async function refreshEolData(): Promise<void> {
  const log = logger.child({ job: EOL_REFRESH_QUEUE });
  log.info("[eolFetcher] Fetching EOL data from endoflife.date");

  try {
    const [phpCycles, nginxCycles, apacheCycles] = await Promise.all([
      fetchEolCycles("php"),
      fetchEolCycles("nginx"),
      fetchEolCycles("apache"),
    ]);

    const phpEol = buildPhpEolMap(phpCycles);
    const nginxEolCycles = buildEolCycleSet(nginxCycles);
    const apacheEolCycles = buildEolCycleSet(apacheCycles);

    cache = { phpEol, nginxEolCycles, apacheEolCycles, fetchedAt: new Date() };

    log.info(
      {
        phpEolEntries: Object.keys(phpEol).length,
        nginxEolCycles: nginxEolCycles.size,
        apacheEolCycles: apacheEolCycles.size,
        fetchedAt: cache.fetchedAt.toISOString(),
      },
      "[eolFetcher] EOL data refreshed successfully",
    );
  } catch (err) {
    log.warn(
      { err },
      "[eolFetcher] EOL data refresh failed — bundled fallback tables remain active",
    );
    // Do NOT update cache so that callers continue to use the last good fetch
    // (or the bundled fallback if no successful fetch has occurred yet).
  }
}

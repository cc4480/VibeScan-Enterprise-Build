/**
 * EOL data fetcher — pulls end-of-life schedules from the endoflife.date API,
 * persists them to the `eol_cache` DB table, and caches them in-process.
 *
 * Three products are fetched in parallel: PHP, Nginx, Apache HTTPD.
 *
 * Persistence strategy:
 *   1. On server startup, `loadEolCacheFromDb()` hydrates the in-memory cache
 *      from the last successful DB write — no network call required.
 *   2. After each successful fetch, `refreshEolData()` writes the full payload
 *      to the DB (upsert on key = "eol-data") so it survives future restarts.
 *   3. The in-memory cache is the hot path for scan-time reads; the DB is the
 *      durable source-of-truth loaded once per process lifetime.
 *
 * Refresh cadence:
 *   • At server startup — `loadEolCacheFromDb()` + non-blocking fetch to freshen
 *   • Daily at 03:00 UTC — pg-boss cron job (EOL_REFRESH_QUEUE)
 *
 * Failure handling:
 *   • Fetch errors → cache is NOT updated; bundled fallback (or last DB load) used
 *   • DB write errors → logged at WARN; in-memory cache is still updated so the
 *     current process has fresh data even if persistence failed
 *   • DB load errors → logged at WARN; fallback to bundled tables
 */

import { logger } from "./logger";
import { setEolCache, type EolCycle, FALLBACK_PHP_EOL, FALLBACK_NGINX_EOL_CYCLES, FALLBACK_APACHE_EOL_CYCLES, cache } from "./eolFetcherData";
import { saveEolCacheToDb } from "./eolFetcherDb";
export { getEolDataFetchedAt, getLivePhpEol, getLiveNginxEolCycles, getLiveApacheEolCycles } from "./eolFetcherData";
export { loadEolCacheFromDb } from "./eolFetcherDb";

// ─── pg-boss queue name (imported by worker.ts) ───────────────────────────────

export const EOL_REFRESH_QUEUE = "eol-refresh";

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
        "User-Agent": "SecScan-SecurityScanner/1.0",
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
 *   - Its EOL date has passed        → "Reached EOL in <Month Year>"
 *   - Its EOL date is within 12 mo   → "Reaches EOL in <Month Year>" (early warning)
 *   - Its EOL date is > 12 mo away   → skipped (still comfortably supported)
 */
function buildPhpEolMap(cycles: EolCycle[]): Record<string, string> {
  const map: Record<string, string> = {};
  const now = new Date();
  const twelveMonthsOut = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  for (const c of cycles) {
    if (c.eol === false || !c.eol) continue;
    const eolDate = new Date(c.eol);
    const eolStr = eolDate.toLocaleDateString("en-US", { month: "long", year: "numeric" });

    if (eolDate <= now) {
      map[c.cycle] = `Reached EOL in ${eolStr}`;
    } else if (eolDate <= twelveMonthsOut) {
      map[c.cycle] = `Reaches EOL in ${eolStr}`;
    }
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
 * Fetches current EOL data for PHP, Nginx, and Apache from endoflife.date,
 * updates the in-memory cache, and persists the result to the DB.
 *
 * Uses Promise.allSettled so that a single provider failure is non-fatal:
 * the successfully fetched products still update the cache, while failed
 * products retain their last known-good (DB-loaded or bundled) values.
 *
 * Called:
 *   - At startup (non-blocking void call from worker.ts, after DB load)
 *   - Daily via pg-boss schedule (EOL_REFRESH_QUEUE)
 *
 * On all-product failure: cache not updated; DB-loaded or bundled data stays.
 * On DB write failure: in-memory cache IS updated; WARN logged.
 */
export async function refreshEolData(): Promise<void> {
  const log = logger.child({ job: EOL_REFRESH_QUEUE });
  log.info("[eolFetcher] Fetching EOL data from endoflife.date");

  const [phpResult, nginxResult, apacheResult] = await Promise.allSettled([
    fetchEolCycles("php"),
    fetchEolCycles("nginx"),
    fetchEolCycles("apache"),
  ]);

  const failed = (
    [
      phpResult.status === "rejected" ? "php" : null,
      nginxResult.status === "rejected" ? "nginx" : null,
      apacheResult.status === "rejected" ? "apache" : null,
    ] as (string | null)[]
  ).filter((p): p is string => p !== null);

  if (failed.length === 3) {
    // All products failed — do not update cache at all
    log.warn(
      { failed, errors: [phpResult, nginxResult, apacheResult].map((r) => r.status === "rejected" ? String(r.reason) : null) },
      "[eolFetcher] All product fetches failed — last persisted / bundled fallback data remains active",
    );
    return;
  }

  if (failed.length > 0) {
    log.warn(
      { failed },
      `[eolFetcher] Partial fetch — ${failed.join(", ")} failed; succeeded products will update cache`,
    );
  }

  // For failed products, fall back to the last cached or bundled values
  const phpEol =
    phpResult.status === "fulfilled"
      ? buildPhpEolMap(phpResult.value)
      : (cache?.phpEol ?? FALLBACK_PHP_EOL);

  const nginxEolCycles =
    nginxResult.status === "fulfilled"
      ? buildEolCycleSet(nginxResult.value)
      : (cache?.nginxEolCycles ?? FALLBACK_NGINX_EOL_CYCLES);

  const apacheEolCycles =
    apacheResult.status === "fulfilled"
      ? buildEolCycleSet(apacheResult.value)
      : (cache?.apacheEolCycles ?? FALLBACK_APACHE_EOL_CYCLES);

  const fetchedAt = new Date();
  const refreshed = { phpEol, nginxEolCycles, apacheEolCycles, fetchedAt };
  setEolCache(refreshed);

  log.info(
    {
      phpEolEntries: Object.keys(phpEol).length,
      nginxEolCycles: nginxEolCycles.size,
      apacheEolCycles: apacheEolCycles.size,
      partialRefresh: failed.length > 0,
      failed: failed.length > 0 ? failed : undefined,
      fetchedAt: fetchedAt.toISOString(),
    },
    "[eolFetcher] EOL data refreshed — persisting to DB",
  );

  // Persist to DB — non-fatal if it fails (in-memory cache is already updated)
  try {
    await saveEolCacheToDb(refreshed);
    log.info("[eolFetcher] EOL data persisted to DB");
  } catch (dbErr) {
    log.warn(
      { err: dbErr },
      "[eolFetcher] DB persist failed — restart may load stale data",
    );
  }
}
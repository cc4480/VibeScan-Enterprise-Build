/** The in-memory end-of-life cache, its fallbacks and the accessors other modules read. */
// ─── endoflife.date API response shape ───────────────────────────────────────

export interface EolCycle {
  cycle: string;        // "8.3", "1.26", "2.4", …
  releaseDate: string;  // ISO date
  eol: string | false;  // ISO EOL date, or false when still actively supported
  latest: string;       // latest patch release in this cycle
  lts?: boolean;
  support?: string | false;
}

// ─── DB payload shape ─────────────────────────────────────────────────────────
//
// Sets cannot be stored in JSON directly — serialised as sorted string arrays.

export interface EolDbPayload {
  phpEol: Record<string, string>;
  nginxEolCycles: string[];
  apacheEolCycles: string[];
}

// ─── Bundled fallback data — mirrors the constants in cveCheck.ts ─────────────
//
// Used when neither in-memory cache nor DB row is available (e.g. first boot
// with no network or DB before the async refresh completes).

export const FALLBACK_PHP_EOL: Record<string, string> = {
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
export const FALLBACK_NGINX_EOL_CYCLES = new Set([
  "1.14", "1.15", "1.16", "1.17", "1.18", "1.19",
  "1.20", "1.21", "1.22", "1.23", "1.24", "1.25",
]);

// Apache HTTPD branches known to be EOL.
export const FALLBACK_APACHE_EOL_CYCLES = new Set(["2.0", "2.2"]);

// ─── In-process cache ─────────────────────────────────────────────────────────

export interface EolCache {
  phpEol: Record<string, string>;
  nginxEolCycles: Set<string>;
  apacheEolCycles: Set<string>;
  fetchedAt: Date;
}

export let cache: EolCache | null = null;

/** Replaces the cache. Assignment has to happen in this module: elsewhere `cache` is a read-only import (readers still see the new value). */
export function setEolCache(next: EolCache): void {
  cache = next;
}

export const EOL_CACHE_KEY = "eol-data";

// ─── Public getters ───────────────────────────────────────────────────────────

/** Returns the timestamp of the last successful EOL data fetch, or null. */
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

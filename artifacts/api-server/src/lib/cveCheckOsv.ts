/** OSV lookups: bounded cache, query, and CVSS/severity/fix extraction. */
import type { ScanVulnerability } from "./scanner";
import { vuln } from "./cveCheckCore";

export const OSV_TIMEOUT_MS = 8_000;

export const OSV_ENDPOINT = "https://api.osv.dev/v1/query";

/** Where OSV is asked: osv.dev unless OSV_API_URL points at a compatible server (a mirror an operator runs, or a test). Read on each call. */
export const osvEndpoint = (): string => process.env["OSV_API_URL"]?.trim() || OSV_ENDPOINT;

// ─────────────────────────────────────────────────────────────────────────────
// IN-PROCESS CACHE — avoids duplicate OSV.dev calls for same version
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Size-bounded Map with LRU eviction.
 *
 * JS Maps preserve insertion order. On `get()` the accessed entry is moved
 * to the end (most-recently-used). On `set()` when the map is full, the
 * first entry (least-recently-used) is deleted before inserting the new key.
 *
 * This gives O(1) get, set, and eviction — no extra bookkeeping needed.
 */
export class BoundedMap<K, V> {
  private readonly map = new Map<K, V>();

  constructor(private readonly maxSize: number) {}

  has(key: K): boolean {
    return this.map.has(key);
  }

  get(key: K): V | undefined {
    if (!this.map.has(key)) return undefined;
    // Move to end (most-recently-used) by deleting and re-inserting
    const value = this.map.get(key)!;
    this.map.delete(key);
    this.map.set(key, value);
    return value;
  }

  clear(): void {
    this.map.clear();
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) {
      // Update existing key — delete first so re-insertion moves it to end
      this.map.delete(key);
    } else if (this.map.size >= this.maxSize) {
      // Evict the least-recently-used entry (first key in insertion order)
      const lruKey = this.map.keys().next().value as K;
      this.map.delete(lruKey);
    }
    this.map.set(key, value);
  }

  get size(): number {
    return this.map.size;
  }
}

/**
 * Maximum number of (package, version, ecosystem) entries to keep in memory.
 * Override via OSV_CACHE_MAX_SIZE env var. Falls back to 1000 if unset or invalid.
 * Exported so the worker can log the effective value at startup.
 */
export const OSV_CACHE_MAX_SIZE = (() => {
  const raw = process.env["OSV_CACHE_MAX_SIZE"];
  if (!raw) return 1_000;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 1_000;
})();

export const osvCache = new BoundedMap<string, OsvVuln[]>(OSV_CACHE_MAX_SIZE);

export function osvCacheKey(packageName: string, version: string, ecosystem: string): string {
  return `${ecosystem}:${packageName}@${version}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// OSV.dev QUERY (with in-process cache)
// ─────────────────────────────────────────────────────────────────────────────

export interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{
    ranges?: Array<{ events?: Array<{ fixed?: string }> }>;
  }>;
}

export async function queryOsv(packageName: string, version: string, ecosystem: string): Promise<OsvVuln[]> {
  const cacheKey = osvCacheKey(packageName, version, ecosystem);
  if (osvCache.has(cacheKey)) {
    return osvCache.get(cacheKey)!;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);
  try {
    const res = await fetch(osvEndpoint(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version,
        package: { name: packageName, ecosystem },
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      // Cache definitive non-2xx responses (e.g. 404 — package not found in OSV)
      osvCache.set(cacheKey, []);
      return [];
    }
    const json = (await res.json()) as { vulns?: OsvVuln[] };
    const vulns = json.vulns ?? [];
    // Only cache definitive successful responses — not transient errors
    osvCache.set(cacheKey, vulns);
    return vulns;
  } catch {
    // Network errors and timeouts are transient — do NOT cache so the next
    // scan can retry. Just return empty for this request.
    return [];
  } finally {
    clearTimeout(timer);
  }
}

export function extractCvss(vuln: OsvVuln): number | null {
  for (const s of vuln.severity ?? []) {
    if (s.type === "CVSS_V3" || s.type === "CVSS_V4") {
      // Parse CVSS score from vector string
      const match = /\/(\d+\.\d+)$/.exec(s.score) || s.score.match(/^(\d+\.\d+)$/);
      if (match) return parseFloat(match[1]);
    }
  }
  // Try database_specific severity
  const dbSev = vuln.database_specific?.severity;
  if (dbSev === "CRITICAL") return 9.0;
  if (dbSev === "HIGH") return 7.5;
  if (dbSev === "MODERATE" || dbSev === "MEDIUM") return 5.5;
  if (dbSev === "LOW") return 3.1;
  return null;
}

export function cvssToSeverity(score: number | null): ScanVulnerability["severity"] {
  if (!score) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

export function extractFixedVersion(osvVuln: OsvVuln): string | null {
  for (const affected of osvVuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

export function cveIds(osvVuln: OsvVuln): string[] {
  return (osvVuln.aliases ?? [osvVuln.id]).filter((id) => id.startsWith("CVE-")).slice(0, 3);
}

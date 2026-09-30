/** Persisting the end-of-life cache to the database and hydrating it at startup. */
import { db, eolCacheTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { logger } from "./logger";
import { setEolCache, EOL_CACHE_KEY, cache, type EolDbPayload, type EolCache } from "./eolFetcherData";

// ─── DB persistence ───────────────────────────────────────────────────────────

/**
 * Loads the last-persisted EOL data from the DB and hydrates the in-memory cache.
 * Call this once at startup (before any scans run) so fresh data is available
 * immediately without waiting for a network fetch to endoflife.date.
 */
export async function loadEolCacheFromDb(): Promise<void> {
  try {
    const [row] = await db
      .select()
      .from(eolCacheTable)
      .where(eq(eolCacheTable.key, EOL_CACHE_KEY))
      .limit(1);

    if (!row) {
      logger.debug("[eolFetcher] No persisted EOL data in DB yet — bundled fallback active");
      return;
    }

    const payload = row.payload as EolDbPayload;
    setEolCache({
      phpEol: payload.phpEol,
      nginxEolCycles: new Set(payload.nginxEolCycles),
      apacheEolCycles: new Set(payload.apacheEolCycles),
      fetchedAt: row.fetchedAt,
    });

    logger.info(
      {
        fetchedAt: row.fetchedAt.toISOString(),
        phpEolEntries: Object.keys(payload.phpEol).length,
        nginxEolCycles: payload.nginxEolCycles.length,
        apacheEolCycles: payload.apacheEolCycles.length,
      },
      "[eolFetcher] Loaded persisted EOL data from DB",
    );
  } catch (err) {
    logger.warn(
      { err },
      "[eolFetcher] Could not load persisted EOL data from DB — bundled fallback active",
    );
  }
}

/** Persists the current cache to the DB (upsert). Errors are non-fatal. */
export async function saveEolCacheToDb(c: EolCache): Promise<void> {
  const payload: EolDbPayload = {
    phpEol: c.phpEol,
    nginxEolCycles: Array.from(c.nginxEolCycles).sort(),
    apacheEolCycles: Array.from(c.apacheEolCycles).sort(),
  };

  await db
    .insert(eolCacheTable)
    .values({ key: EOL_CACHE_KEY, payload, fetchedAt: c.fetchedAt })
    .onConflictDoUpdate({
      target: eolCacheTable.key,
      set: { payload, fetchedAt: c.fetchedAt },
    });
}

/**
 * Scheduled re-verification of domain ownership.
 *
 * A verification only unlocks active probing for VERIFICATION_VALID_DAYS after
 * the proof was last seen (see activeProbeGate.ts). This job is what keeps a
 * live one alive: every pass looks for the DNS record or well-known file again,
 * with the SAME check the user passed (runVerificationCheck, which already
 * applies the SSRF rules), and moves `verified_at` forward when it is still
 * there.
 *
 * When the proof is gone the row is left alone and simply lapses once
 * VERIFICATION_VALID_DAYS have passed since the last success. A domain that was
 * sold or abandoned therefore stops being open to its previous owner, while a
 * short DNS outage or one flaky fetch costs nothing, since the next daily pass
 * tries again.
 */
import { db, domainVerificationsTable } from "@workspace/db";
import { and, eq, isNotNull, isNull, lt, or, sql } from "drizzle-orm";
import { runVerificationCheck, type VerificationMethod } from "./domainVerify";
import { logger } from "./logger";

/** Domains checked at the same time. Each check is a DNS lookup plus at most one HTTPS request. */
export const REVERIFY_CONCURRENCY = 5;
/**
 * Most rows looked at in one pass, so a pass is bounded however many domains
 * exist. Oldest-checked first, and every row looked at is stamped, so the rows
 * beyond the cap are reached on the next pass rather than starved.
 */
export const REVERIFY_MAX_PER_RUN = 1000;
/**
 * A row looked at more recently than this is skipped, so the pass that runs at
 * worker start does not repeat what the daily one just did, and several replicas
 * starting together do not all hit the same domains.
 */
export const REVERIFY_MIN_INTERVAL_HOURS = 12;
/** One domain's whole check, as a backstop. The checks carry their own shorter timeouts. */
const PER_DOMAIN_TIMEOUT_MS = 30_000;

export type VerifyFn = (domain: string, token: string) => Promise<VerificationMethod | null>;

export interface ReverifyOptions {
  /** The proof check. Defaults to the one the check endpoint uses; injectable for tests. */
  verify?: VerifyFn;
  concurrency?: number;
  maxPerRun?: number;
  minIntervalHours?: number;
  now?: Date;
}

export interface ReverifyResult {
  /** Proof found again; verified_at moved to now. */
  refreshed: number;
  /** Proof not found; verified_at left alone. */
  failed: number;
  /** The check or the update threw; verified_at left alone. */
  errored: number;
  /** More rows were due than maxPerRun; the rest wait for the next pass. */
  capped: boolean;
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`verification check timed out after ${ms}ms`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}

export async function reverifyDomains(opts: ReverifyOptions = {}): Promise<ReverifyResult> {
  const verify = opts.verify ?? runVerificationCheck;
  const concurrency = Math.max(1, opts.concurrency ?? REVERIFY_CONCURRENCY);
  const maxPerRun = Math.max(1, opts.maxPerRun ?? REVERIFY_MAX_PER_RUN);
  const minIntervalHours = opts.minIntervalHours ?? REVERIFY_MIN_INTERVAL_HOURS;
  const now = opts.now ?? new Date();
  const recentCutoff = new Date(now.getTime() - minIntervalHours * 3_600_000);
  const t = domainVerificationsTable;

  // Every row that has ever been verified, including ones that have already
  // lapsed: after a deploy this is what brings rows older than the window back,
  // and a lapsed row whose proof is back is simply verified again. One more row
  // than the cap is read to learn whether the cap bit.
  const found = await db
    .select({ id: t.id, domain: t.domain, token: t.token })
    .from(t)
    .where(and(isNotNull(t.verifiedAt), or(isNull(t.lastCheckedAt), lt(t.lastCheckedAt, recentCutoff))))
    .orderBy(sql`${t.lastCheckedAt} ASC NULLS FIRST`)
    .limit(maxPerRun + 1);
  const capped = found.length > maxPerRun;
  const rows = capped ? found.slice(0, maxPerRun) : found;

  const result: ReverifyResult = { refreshed: 0, failed: 0, errored: 0, capped };

  const handle = async (row: (typeof rows)[number]): Promise<void> => {
    try {
      const method = await withTimeout(verify(row.domain, row.token), PER_DOMAIN_TIMEOUT_MS);
      if (method) {
        await db.update(t).set({ verifiedAt: now, lastCheckedAt: now, method }).where(eq(t.id, row.id));
        result.refreshed++;
      } else {
        // verified_at is deliberately untouched: the row lapses on its own once
        // the window passes. Only lastCheckedAt moves, so a domain that keeps
        // failing goes to the back of the queue instead of crowding out the rest.
        await db.update(t).set({ lastCheckedAt: now }).where(eq(t.id, row.id));
        result.failed++;
        logger.debug({ domain: row.domain }, "Domain proof not found on re-verification");
      }
    } catch (err) {
      // One domain's failure (a DNS error, a timeout, a database hiccup) must not stop the rest.
      result.errored++;
      logger.warn({ err, domain: row.domain }, "Domain re-verification errored");
    }
  };

  // A small pool: each worker takes the next unclaimed row until none are left.
  let next = 0;
  const worker = async (): Promise<void> => {
    for (let i = next++; i < rows.length; i = next++) await handle(rows[i]!);
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, rows.length) }, worker));

  const log = { checked: rows.length, ...result };
  if (capped) {
    logger.warn(log, "Domain re-verification hit its per-run cap; the remaining domains wait for the next run");
  } else {
    logger.info(log, "Domain re-verification finished");
  }
  return result;
}

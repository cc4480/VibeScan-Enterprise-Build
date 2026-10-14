import { processScanJob } from "./workerJob";
import { and } from "drizzle-orm";
import { getBoss, SCAN_QUEUE, type ScanJobData } from "./queue";
import { purgeExpiredOobTokens } from "./oobServer";
import { purgeExpiredSessions } from "./auth";
import { purgeStaleTrialUsage } from "./freeTrial";
import { purgeStaleTokens } from "./authTokens";
import { warnIfLocalDataStale, OSV_CACHE_MAX_SIZE } from "./cveCheck";
import { refreshEolData, loadEolCacheFromDb, EOL_REFRESH_QUEUE } from "./eolFetcher";
import { initBrowser } from "./browser";
import { logger } from "./logger";
import { reapStuckScans } from "./billing";
import { reverifyDomains } from "./domainReverify";

const OOB_PURGE_QUEUE = "oob-purge";
const STUCK_SCAN_QUEUE = "stuck-scan-cleanup";
const DOMAIN_REVERIFY_QUEUE = "domain-reverify";

export async function startWorker(): Promise<void> {
  // Log the effective OSV cache size so operators can confirm env var took effect
  logger.info(
    { osvCacheMaxSize: OSV_CACHE_MAX_SIZE, envVar: "OSV_CACHE_MAX_SIZE" },
    "[cveCheck] OSV cache initialised",
  );

  // Launch headless browser for SPA rendering (deep tier scans).
  // Non-fatal — scanner falls back to raw fetch if Chromium is unavailable.
  await initBrowser();

  // Shutdown is handled in secscan.ts, which drains running scans first and then closes the browser.
  // A handler here that exited at once used to win that race and kill every scan in flight.

  // Hydrate EOL cache from the last DB-persisted fetch BEFORE the staleness check
  // so that warnIfLocalDataStale() uses the live fetchedAt timestamp, not the
  // bundled LOCAL_VULN_DATA_UPDATED date, when persisted data is available.
  await loadEolCacheFromDb();

  // Check freshness — uses live DB timestamp when available, bundled date otherwise
  warnIfLocalDataStale();

  const boss = await getBoss();

  // pg-boss v12 requires queues to be explicitly created before workers can bind
  await boss.createQueue(SCAN_QUEUE, {
    retryLimit: 2,
    retryDelay: 30,
    expireInSeconds: 7200,
  });

  // How many scans this worker process runs at once.
  //
  // Was a hard-coded 2, which made the whole product a two-lane road: with a
  // median scan of ~26s (p90 38s), 100 people scanning at launch meant 50 waves
  // and a ~22-minute wait for the last one — long enough that they conclude it
  // is broken and leave. Meanwhile the container sits at 0.23 GB of a 7.45 GB
  // limit, so the constraint was arbitrary rather than physical.
  //
  // 8 is deliberate, not maximal. A scan holds a headless Chromium plus
  // hundreds of sockets; at a few hundred MB each, 8 lands near 2 GB and leaves
  // roughly 3x headroom on this container. The failure mode of guessing too
  // high is an OOM kill that drops every in-flight scan at once, so this moves
  // in one step with room to observe rather than straight to the ceiling.
  //
  // Env-overridable so the next move needs no deploy: raise
  // SCAN_WORKER_CONCURRENCY, watch /sys/fs/cgroup/memory.current during a
  // burst, and only then raise it again. Total fleet capacity is
  // replicas x this number.
  const scanConcurrency = Math.max(1, Number(process.env.SCAN_WORKER_CONCURRENCY) || 8);
  logger.info({ scanConcurrency }, "Scan worker concurrency");

  await boss.work<ScanJobData>(SCAN_QUEUE, { localConcurrency: scanConcurrency }, async (jobs) => {
    for (const job of jobs) {
      try {
        await processScanJob(job);
      } catch (err) {
        logger.error({ err, jobId: job.id }, "Unexpected error processing scan job");
        throw err;
      }
    }
  });

  logger.info({ queue: SCAN_QUEUE }, "Scan worker registered and listening");

  // ── Stuck-scan cleanup ────────────────────────────────────────────────────
  // Fails and refunds scans whose job died without reaching a failure path.
  // See reapStuckScans. Every 15 minutes; schedule() upserts by name, so
  // replicas share one schedule.
  await boss.createQueue(STUCK_SCAN_QUEUE);
  await boss.schedule(STUCK_SCAN_QUEUE, "*/15 * * * *", {});
  await boss.work(STUCK_SCAN_QUEUE, async () => {
    const { failed, refunded } = await reapStuckScans();
    if (failed > 0) logger.warn({ failed, refunded }, "Failed and refunded scans that never finished");
  });

  // ── EOL data auto-refresh ─────────────────────────────────────────────────
  // Scheduled daily at 03:00 UTC to keep PHP / Nginx / Apache EOL tables
  // current without manual code changes (fetches from endoflife.date API).
  await boss.createQueue(EOL_REFRESH_QUEUE);
  await boss.schedule(EOL_REFRESH_QUEUE, "0 3 * * *", {});
  await boss.work(EOL_REFRESH_QUEUE, async () => {
    await refreshEolData();
  });
  logger.info(
    { queue: EOL_REFRESH_QUEUE, cron: "0 3 * * *" },
    "EOL refresh schedule registered (daily 03:00 UTC)",
  );

  // Kick off a fresh fetch in the background to update the in-memory cache and DB.
  // Failures are logged at WARN; the DB-loaded or bundled fallback data stays active.
  void refreshEolData();

  // Drop expired out-of-band tokens and their interactions on the same daily
  // schedule, so a busy scanner does not accumulate them without bound.
  await boss.createQueue(OOB_PURGE_QUEUE);
  await boss.schedule(OOB_PURGE_QUEUE, "30 3 * * *", {});
  await boss.work(OOB_PURGE_QUEUE, async () => {
    await purgeExpiredOobTokens();
    // Same daily pass: expired sessions and spent or long-expired sign-in tokens.
    await purgeExpiredSessions();
    await purgeStaleTokens();
    await purgeStaleTrialUsage();
  });

  // ── Domain re-verification ────────────────────────────────────────────────
  // A domain verification lapses VERIFICATION_VALID_DAYS after the proof was
  // last seen, so it has to be looked for again to stay valid. See
  // lib/domainReverify.ts. Daily at 04:15 UTC, after the other daily jobs.
  // retryLimit 0: a pass is idempotent and the next one retries every domain
  // anyway, and a retry would only repeat the outbound checks. The expiry is
  // raised above the 15-minute default because a pass over many domains with
  // 5 checks in flight can run longer than that.
  await boss.createQueue(DOMAIN_REVERIFY_QUEUE, { retryLimit: 0, expireInSeconds: 3600 });
  await boss.schedule(DOMAIN_REVERIFY_QUEUE, "15 4 * * *", {});
  await boss.work(DOMAIN_REVERIFY_QUEUE, async () => {
    await reverifyDomains();
  });
  logger.info(
    { queue: DOMAIN_REVERIFY_QUEUE, cron: "15 4 * * *" },
    "Domain re-verification schedule registered (daily 04:15 UTC)",
  );

  // One pass shortly after start. Without it, rows verified before this job
  // existed would be refused by the gate once they pass VERIFICATION_VALID_DAYS
  // and stay refused until the next daily run. Sent as a job rather than run
  // inline so only one replica does it: the singleton key lets one send through
  // per hour across the fleet. The delay lets the process finish starting.
  try {
    await boss.send(DOMAIN_REVERIFY_QUEUE, {}, { startAfter: 60, singletonKey: "startup", singletonSeconds: 3600 });
  } catch (err) {
    logger.warn({ err }, "Could not queue the startup domain re-verification; the daily run will cover it");
  }
}

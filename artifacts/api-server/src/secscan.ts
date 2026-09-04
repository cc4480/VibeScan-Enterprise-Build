/**
 * secscan — the scanner process.
 *
 * Runs the pg-boss worker and the monitor scheduler, and nothing else. There is
 * no HTTP listener here: the only way work reaches this process is the
 * `scan-job` queue in Postgres, which seclayer (the web tier) writes to.
 *
 * Splitting this out of the web process is what lets the two scale
 * independently — scans are long, CPU-heavy and hold a Chromium instance, while
 * web requests are short. It also keeps Playwright out of the web image
 * entirely; `browser.ts` is imported only from `scanner.ts` and `worker.ts`,
 * both of which live on this side of the split.
 */

import { logger } from "./lib/logger";
import { getBoss } from "./lib/queue";

async function main(): Promise<void> {
  await getBoss();
  logger.info("Job queue ready");

  const { startWorker } = await import("./lib/worker");
  await startWorker();

  const { startMonitorScheduler } = await import("./lib/monitorScheduler");
  await startMonitorScheduler();

  logger.info("secscan ready — waiting for scan jobs");
}

main().catch((err: unknown) => {
  // Unlike the web tier, there is no useful degraded mode here: a scanner that
  // cannot reach the queue has no work to do, so fail loudly and let the
  // supervisor restart it rather than idling silently.
  logger.error({ err }, "secscan failed to start");
  process.exit(1);
});

// Drain in-flight scan jobs before exiting. A scan killed mid-run leaves its row
// stuck in "scanning" forever, so the 90 s grace period matters more here than
// it does for the web tier.
process.on("SIGTERM", () => {
  logger.info("SIGTERM received — draining in-flight scan jobs before exit");
  getBoss()
    .then(async (boss) => {
      await boss.stop({ graceful: true, timeout: 90_000 });
      logger.info("pg-boss drained — exiting cleanly");
    })
    .catch((err: unknown) => {
      logger.error({ err }, "Error draining pg-boss on shutdown");
    })
    .finally(() => {
      process.exit(0);
    });
});

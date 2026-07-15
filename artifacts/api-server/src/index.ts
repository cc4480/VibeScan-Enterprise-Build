import app from "./app";
import { logger } from "./lib/logger";
import { getBoss } from "./lib/queue";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

// Initialize pg-boss and start the scan worker + monitor scheduler
getBoss()
  .then(async () => {
    logger.info("Job queue ready");

    const { startWorker } = await import("./lib/worker");
    await startWorker();

    const { startMonitorScheduler } = await import("./lib/monitorScheduler");
    await startMonitorScheduler();
  })
  .catch((err: unknown) => {
    logger.error({ err }, "Failed to initialize job queue — scans will not be processed");
  });

// Graceful shutdown — stop pg-boss before exiting so in-flight scan jobs can
// complete rather than being abandoned mid-execution (which leaves scans stuck
// in "scanning" state).  Replit sends SIGTERM when deploying a new version;
// giving the old process 90 s to drain is enough for most scans to finish.
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

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
});

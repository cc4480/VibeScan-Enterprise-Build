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

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
});

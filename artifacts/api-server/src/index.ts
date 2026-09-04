/**
 * seclayer — the web process.
 *
 * Serves the API and the built frontend. Scan work is handed to secscan through
 * the `scan-job` pg-boss queue rather than executed here, so this process holds
 * no Chromium and stays cheap to scale horizontally.
 */

import app from "./app";
import { logger } from "./lib/logger";
import { getBoss } from "./lib/queue";
import { installCrashHandlers } from "./lib/crashHandlers";
import { warnIfPaymentsMisconfigured } from "./lib/stripe";
import { refreshCloudflareIps } from "./lib/cloudflareIps";
import { behindCloudflare } from "./lib/clientIp";

installCrashHandlers("seclayer");
warnIfPaymentsMisconfigured(logger);

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

// Keep Cloudflare's edge ranges current. They decide whether a request really
// came through Cloudflare, which decides whose address the rate limiters count
// against — so a stale list quietly degrades attribution rather than failing
// loudly. Bundled values cover a failed refresh; only the web tier needs this,
// since the scanner has no callers to identify.
if (behindCloudflare()) {
  void refreshCloudflareIps();
  const DAILY_MS = 24 * 60 * 60_000;
  setInterval(() => void refreshCloudflareIps(), DAILY_MS).unref();
}

// Warm the pg-boss connection at startup so the first user-triggered scan does
// not pay the connection cost. Enqueueing is all this process does with the
// queue — the worker and the monitor scheduler run in secscan.
getBoss()
  .then(() => {
    logger.info("Job queue ready");
  })
  .catch((err: unknown) => {
    logger.error({ err }, "Failed to initialize job queue — scans cannot be queued");
  });

// Stop accepting new work before exiting. The web tier holds no in-flight scans,
// so there is nothing to drain beyond closing the queue connection.
process.on("SIGTERM", () => {
  logger.info("SIGTERM received — shutting down");
  getBoss()
    .then((boss) => boss.stop({ graceful: true, timeout: 10_000 }))
    .catch((err: unknown) => {
      logger.error({ err }, "Error closing queue connection on shutdown");
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

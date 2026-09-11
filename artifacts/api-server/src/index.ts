/**
 * web — the web process.
 *
 * Named `web`, not `seclayer`: Seclayer is a separate product on its own
 * domain, and having this tier answer to that name is one `railway link` away
 * from deploying one product onto the other.
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
import { migrateToLatest } from "@workspace/db";

installCrashHandlers("web");
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

async function start(): Promise<void> {
  // Bring the schema up to date BEFORE anything can serve a request.
  //
  // Until this existed, migrations reached production only by hand, through a
  // procedure that involved briefly exposing Postgres to the internet
  // (deploy/railway/NOTES.md) — a step that had to be remembered before every
  // schema-dependent deploy, and whose omission is silent until the first
  // request touches a missing table. Both services have already booted against
  // a database missing `eol_cache` and logged it at length.
  //
  // secscan runs this too. They share one database and start together, which is
  // exactly why migrateToLatest takes an advisory lock; whoever loses the race
  // waits and then finds nothing to apply.
  const databaseUrl = process.env["DATABASE_URL"];
  if (!databaseUrl) throw new Error("DATABASE_URL environment variable is required but was not provided.");
  await migrateToLatest(databaseUrl, (msg) => logger.info(msg));

  // Warm the pg-boss connection at startup so the first user-triggered scan does
  // not pay the connection cost. Enqueueing is all this process does with the
  // queue — the worker and the monitor scheduler run in secscan. After the
  // migration, so the two are not creating schema at the same time.
  //
  // Still not fatal: a web tier that cannot reach the queue can serve every
  // page and every report, and only scan submission degrades. That is a real
  // degraded mode worth having, unlike a missing schema.
  getBoss()
    .then(() => {
      logger.info("Job queue ready");
    })
    .catch((err: unknown) => {
      logger.error({ err }, "Failed to initialize job queue — scans cannot be queued");
    });

  app.listen(port, (err) => {
    if (err) {
      logger.error({ err }, "Error listening on port");
      process.exit(1);
    }

    logger.info({ port }, "Server listening");
  });
}

start().catch((err: unknown) => {
  // Deliberately fatal. A process that cannot establish its schema must fail
  // the deploy rather than come up and throw on every request that touches a
  // table it does not have.
  logger.error({ err }, "web failed to start");
  process.exit(1);
});

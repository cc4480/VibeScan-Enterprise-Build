/**
 * Last-resort error capture for both services.
 *
 * Neither entrypoint handled `unhandledRejection` or `uncaughtException`, which
 * meant the failures most worth knowing about were the ones that produced the
 * least evidence: Node prints a raw stack to stderr and exits, so there is no
 * structured record, no service name, and nothing an aggregator can key on.
 *
 * Two things happen here. Always: a structured fatal log, so whatever ships
 * stdout gets a record with the same shape as every other log line. Optionally,
 * when ALERT_WEBHOOK_URL is set: one POST so somebody finds out without reading
 * container logs.
 *
 * Deliberately not a vendor SDK. This is the floor — a crash is recorded and
 * can page someone — and it adds no dependency. Real error tracking (grouping,
 * release health, breadcrumbs) is a product decision and a separate one.
 */

import { logger } from "./logger";
import { checkUrlSafe } from "./ssrfGuard";

/** Give the log transport a moment to flush before the process goes away. */
const FLUSH_MS = 250;
const ALERT_TIMEOUT_MS = 3_000;

let installed = false;

function describe(err: unknown): { message: string; stack?: string } {
  if (err instanceof Error) {
    return { message: err.message, stack: err.stack ?? undefined };
  }
  return { message: typeof err === "string" ? err : JSON.stringify(err) };
}

/**
 * Fire-and-forget alert. Never throws: a failure to report a crash must not
 * become a second crash, and must not delay the exit beyond its timeout.
 */
async function alert(service: string, kind: string, detail: string): Promise<void> {
  const url = process.env["ALERT_WEBHOOK_URL"];
  if (!url) return;

  // The URL comes from configuration rather than a user, but it is still a
  // destination we POST to — the same guard the webhook path uses.
  const safe = await checkUrlSafe(url, { requireHttps: true });
  if (!safe.ok) {
    logger.warn({ reason: safe.reason }, "ALERT_WEBHOOK_URL rejected — not alerting");
    return;
  }

  try {
    await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        text: `🚨 ${service}: ${kind}\n${detail.slice(0, 1500)}`,
      }),
      signal: AbortSignal.timeout(ALERT_TIMEOUT_MS),
    });
  } catch {
    // Nothing useful to do here; the fatal log above is the durable record.
  }
}

/**
 * @param service  Name recorded on every crash — "seclayer" or "secscan".
 * @param onFatal  Optional cleanup (draining a queue, say) before exit.
 */
export function installCrashHandlers(
  service: string,
  onFatal?: () => Promise<void> | void,
): void {
  if (installed) return;
  installed = true;

  const die = (kind: string) => (err: unknown) => {
    const { message, stack } = describe(err);
    logger.fatal({ service, kind, err: { message, stack } }, `${service}: ${kind}`);

    void (async () => {
      await alert(service, kind, stack ?? message);
      try {
        await onFatal?.();
      } catch {
        // Cleanup failing during a crash is not worth masking the crash itself.
      }
      setTimeout(() => process.exit(1), FLUSH_MS).unref();
    })();
  };

  // An unhandled rejection leaves the process in an unknown state. Node's own
  // default is to terminate, and pretending otherwise is how a service ends up
  // half-alive: accepting requests it can no longer serve.
  process.on("unhandledRejection", die("unhandled promise rejection"));
  process.on("uncaughtException", die("uncaught exception"));
}

/**
 * Liveness for a process with no HTTP listener.
 *
 * secscan deliberately exposes no port — work reaches it only through the
 * queue — which also means there is no endpoint to health-check. Without a
 * signal, a worker that has lost its database connection, wedged on a hung
 * browser, or stopped polling looks exactly like a worker with nothing to do.
 *
 * So the worker touches a file on a timer, and the container healthcheck asks
 * how old it is. The timer is deliberately not tied to job processing: an idle
 * scanner is healthy, and tying the two would report a quiet queue as a
 * failure. What it does prove is that the process is alive, its event loop is
 * turning, and its connection to pg-boss was established.
 */

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { logger } from "./logger";

/** Overridable so the healthcheck and the writer cannot disagree about the path. */
export function heartbeatPath(): string {
  return process.env["HEARTBEAT_FILE"] ?? path.join("/tmp", "secscan-heartbeat");
}

const INTERVAL_MS = 15_000;

let timer: NodeJS.Timeout | null = null;

async function touch(): Promise<void> {
  const file = heartbeatPath();
  try {
    // Written to a sibling and renamed rather than written in place. The
    // healthcheck is a separate process and can read at any moment, including
    // the moment between a file being created and its bytes arriving — an
    // in-place write leaves a window where the reader sees an empty file and
    // reports a healthy worker as dead. rename() is atomic within a
    // filesystem, so a reader sees either the old timestamp or the new one.
    const tmp = `${file}.tmp`;
    await fsp.writeFile(tmp, String(Date.now()), "utf8");
    await fsp.rename(tmp, file);
  } catch (err) {
    // A failure here must not take the worker down: the scanner losing its
    // liveness file is a monitoring problem, not a reason to stop scanning.
    logger.warn({ err, file }, "Could not write heartbeat file");
  }
}

export function startHeartbeat(): void {
  if (timer) return;
  void touch();
  timer = setInterval(() => void touch(), INTERVAL_MS);
  // Do not hold the process open on this alone.
  timer.unref();
  logger.info({ file: heartbeatPath(), intervalMs: INTERVAL_MS }, "Heartbeat started");
}

export function stopHeartbeat(): void {
  if (!timer) return;
  clearInterval(timer);
  timer = null;
}

/**
 * Reads the heartbeat and reports whether it is recent enough.
 * Used by the container healthcheck, which runs this in a separate process.
 */
export function isHeartbeatFresh(maxAgeMs: number, now: number = Date.now()): boolean {
  try {
    const raw = fs.readFileSync(heartbeatPath(), "utf8").trim();
    // Number("") is 0, which is finite — so an empty file would otherwise read
    // as a timestamp from 1970 rather than as no timestamp at all. Same answer
    // here (not fresh), but for a reason that survives someone changing the
    // comparison below.
    if (!raw) return false;
    const at = Number(raw);
    if (!Number.isFinite(at) || at <= 0) return false;
    return now - at <= maxAgeMs;
  } catch {
    // Missing file means the worker has not started yet, or has never written.
    return false;
  }
}

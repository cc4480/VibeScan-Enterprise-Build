/**
 * What a running scan has finished so far, saved where the progress page can read it.
 *
 * The page used to play a script on a timer, so what it showed had no connection
 * to what the scanner was doing (including a "no path traversal detected" line
 * for every site). The test ledger already knows each test's real outcome the
 * moment it ends; this writes that to the scan row while the scan runs.
 *
 * Writes are batched: tests finish in bursts, and one update per test would be
 * dozens of writes a second. A failed write is logged and dropped. Progress is
 * a display, and the scan must never fail or slow down because of it.
 */
import { db, scansTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { logger } from "./logger";
import type { TestRecord } from "./testLedger";

/** How long finished tests may wait before being written. */
export const LIVE_FLUSH_MS = 700;

export interface LiveProgress {
  /** Record one finished test. Safe to pass straight to TestLedger as its listener. */
  add(record: TestRecord): void;
  /** Write anything still waiting and stop the timer. Call once the scan is over, however it ended. */
  finish(): Promise<void>;
}

export function createLiveProgress(scanId: string, flushMs = LIVE_FLUSH_MS): LiveProgress {
  const records: TestRecord[] = [];
  let timer: ReturnType<typeof setTimeout> | null = null;
  let writing: Promise<void> = Promise.resolve();

  const write = (): Promise<void> => {
    // Serialised: a slow write must not be overtaken by a newer, shorter list.
    writing = writing.then(async () => {
      try {
        await db.update(scansTable).set({ liveTests: [...records] }).where(eq(scansTable.id, scanId));
      } catch (err) {
        logger.warn({ err, scanId }, "Could not save live scan progress");
      }
    });
    return writing;
  };

  return {
    add(record) {
      records.push(record);
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        void write();
      }, flushMs);
    },
    async finish() {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (records.length > 0) await write();
      else await writing;
    },
  };
}
